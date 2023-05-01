package izbernet

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	insecureRand "math/rand"
)

const BULLETIN_RANDOM_SIZE = 4

type Bulletin []byte
type BulletinList []Bulletin
type BulletinListSending struct {
	Bulletins       BulletinList
	VoterChainIndex int
}

type VoterActor struct {
	selfIndexInChain     int
	votersChain          []Voter
	privateKey           *rsa.PrivateKey
	randoms              [][]byte
	networkChannelOutput chan BulletinListSending
	networkChannelInput  chan BulletinListSending
}

func NewVoterActor(voting Voting, privateKey *rsa.PrivateKey, netOutput chan BulletinListSending, netInput chan BulletinListSending) (*VoterActor, error) {
	v := VoterActor{}
	v.privateKey = privateKey
	v.votersChain = voting.Voters
	publicKey := privateKey.PublicKey
	v.selfIndexInChain = -1
	v.networkChannelInput = netInput
	v.networkChannelOutput = netOutput

	for i := 0; i < len(voting.Voters); i++ {

		if voting.Voters[i].PublicKey == publicKey {
			v.selfIndexInChain = i
			break
		}
	}

	if v.selfIndexInChain == -1 {
		return nil, errors.New("you are not in this voting")
	}

	return &v, nil
}

func getBulletinRandom() ([]byte, error) {
	randomBytes := make([]byte, BULLETIN_RANDOM_SIZE)
	_, err := rand.Reader.Read(randomBytes)
	if err != nil {
		return nil, err
	}

	return randomBytes, nil
}

const AES_BLOCK_SIZE_BYTES = 16

func encryptedKeySize(pub *rsa.PublicKey) int {
	return pub.N.BitLen() / 8
}

func encryptRSA(pub *rsa.PublicKey, data []byte) []byte {
	// random AES KEY
	key := make([]byte, AES_BLOCK_SIZE_BYTES)
	encryptedKey := make([]byte, encryptedKeySize(pub))
	encryptedData := make([]byte, len(data))

	rand.Reader.Read(key)
	c, _ := aes.NewCipher(key)

	nonce := make([]byte, AES_BLOCK_SIZE_BYTES) // nonce = 0 is OK (key is random)

	aes := cipher.NewCTR(c, nonce)
	encryptedKeyInt := new(big.Int)
	encryptedKeyInt.Exp(new(big.Int).SetBytes(key), big.NewInt(int64(pub.E)), pub.N)
	encryptedKeyInt.FillBytes(encryptedKey)

	aes.XORKeyStream(encryptedData, data)
	return append(encryptedKey, encryptedData...)
}

func decryptRSA(priv *rsa.PrivateKey, data []byte) []byte {
	key := make([]byte, AES_BLOCK_SIZE_BYTES)

	encKeySize := encryptedKeySize(&priv.PublicKey)
	encryptedKey := data[:encKeySize]
	encryptedData := data[encKeySize:]

	decryptedData := make([]byte, len(encryptedData))

	keyInt := new(big.Int)
	keyInt.Exp(new(big.Int).SetBytes(encryptedKey), priv.D, priv.N)
	keyInt.FillBytes(key)

	c, _ := aes.NewCipher(key)
	nonce := make([]byte, AES_BLOCK_SIZE_BYTES)
	aes := cipher.NewCTR(c, nonce)
	aes.XORKeyStream(decryptedData, encryptedData)

	return decryptedData
}

func dataHash(data []byte) ([]byte, error) {
	msgHash := sha512.New()
	_, err := msgHash.Write(data)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)
	return msgHashSum, nil
}

func sign(priv *rsa.PrivateKey, data []byte) ([]byte, error) {
	msgHashSum, _ := dataHash(data)
	signature, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA512, msgHashSum, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

func verify(pub *rsa.PublicKey, sign []byte, data []byte) error {
	msgHashSum, _ := dataHash(data)
	err := rsa.VerifyPSS(pub, crypto.SHA512, msgHashSum, sign, nil)
	return err
}

const SIGNATURE_SIZE_BYTES = 256

func deleteSignature(data []byte) []byte {
	return data[:len(data)-SIGNATURE_SIZE_BYTES]
}

func (v *VoterActor) signBulletins(bulletins BulletinList) error {
	for i := 0; i < len(v.votersChain); i++ {
		signature, err := sign(v.privateKey, bulletins[i])
		if err != nil {
			return err
		}
		bulletins[i] = append(bulletins[i], signature...)
	}
	return nil
}

func (v *VoterActor) verifyBulletins(bulletins BulletinList, publicKey *rsa.PublicKey) error {
	for i := 0; i < len(v.votersChain); i++ {
		signature := bulletins[i][len(bulletins[i])-SIGNATURE_SIZE_BYTES:]
		b := bulletins[i][:len(bulletins[i])-SIGNATURE_SIZE_BYTES]
		//fmt.Printf("bull: %v, sign: %v, hash: %v\n", len(bulletins[i]), len(sign), len(msgHashSum))
		err := verify(publicKey, signature, b)
		if err != nil {
			fmt.Printf("incorrect signature %v\n", len(signature))
			return nil
		} else {
			//print("signature verified\n")
			//bulletins[i] = deleteSignature(bulletins[i])
		}
	}
	return nil
}

func (v *VoterActor) createBulletin(data []byte) (Bulletin, error) {
	y := data
	randomBytes, err := getBulletinRandom()
	if err != nil {
		return nil, err
	}

	v.randoms = append(v.randoms, randomBytes)

	// x||r
	y = append(y, randomBytes...)

	// E_0(E_1(E_2(x||r)))
	for i := len(v.votersChain) - 1; i >= 0; i-- {
		// Encrypt
		publicKey := v.votersChain[i].PublicKey
		y = encryptRSA(&publicKey, y)

		if err != nil {
			return nil, err
		}

	}
	// E_0(E_1(E_2(x||r_i))) ???
	for i := len(v.votersChain) - 1; i >= 0; i-- {
		// Encrypt with random
		randomBytes, err := getBulletinRandom()
		if err != nil {
			return nil, err
		}

		v.randoms = append(v.randoms, randomBytes)

		y = append(y, randomBytes...)
		publicKey := v.votersChain[i].PublicKey
		y = encryptRSA(&publicKey, y)

		if err != nil {
			return nil, err
		}
	}

	return y, nil
}

func (v *VoterActor) decryptBulletins1(bulletins BulletinList) error {
	foundMyBulletin := false

	for i := 0; i < len(bulletins); i++ {
		b := decryptRSA(v.privateKey, bulletins[i])

		if !foundMyBulletin {
			bRand := b[len(b)-BULLETIN_RANDOM_SIZE:]
			for j := 0; j < len(v.randoms); j++ {
				if bytes.Equal(bRand, v.randoms[j]) {
					foundMyBulletin = true
				}
			}
		}

		bulletins[i] = b[:len(b)-BULLETIN_RANDOM_SIZE]
	}

	if !foundMyBulletin {
		return errors.New("cannot find my bulletin (decrypt bulletins first round)")
	}

	return nil
}

func (v *VoterActor) recvBulletinsPrevVoter() BulletinList {
	n := len(v.votersChain)
	prevVoter := (n + v.selfIndexInChain - 1) % n
	for {
		bl, voter := v.recv()
		if voter == prevVoter {
			return bl
		}
	}
}

func (v *VoterActor) getBulletins1() (BulletinList, error) {
	bulletins := make(BulletinList, len(v.votersChain))

	if v.selfIndexInChain == 0 {
		// get 1 bulletin from each user
		bulletinsCount := 0
		for bulletinsCount < len(v.votersChain) {
			bl, voter := v.recv()
			if (len(bl) == 1) && bulletins[voter] == nil {
				bulletins[voter] = bl[0]
				bulletinsCount++
			}
		}
	} else {
		// get all bulletin from prev user
		bulletins = v.recvBulletinsPrevVoter()
	}

	if len(bulletins) != len(v.votersChain) {
		return nil, errors.New("bad bulletins count #1")
	}

	// Shuffle
	randBytes := make([]byte, 64)
	_, err := rand.Read(randBytes)
	if err != nil {
		return nil, err
	}

	randInt := int64(binary.BigEndian.Uint64(randBytes))

	insecureRand.Seed(randInt)
	insecureRand.Shuffle(len(bulletins), func(i int, j int) {
		bulletins[i], bulletins[j] = bulletins[j], bulletins[i]
	})

	return bulletins, nil
}

func (v *VoterActor) getBulletins2() (BulletinList, error) {
	bl := v.recvBulletinsPrevVoter()
	if len(bl) != len(v.votersChain) {
		return nil, errors.New("bad bulletins count #2")
	}

	return bl, nil
}

func (v *VoterActor) decryptBulletins2(bulletins BulletinList) error {
	for i := 0; i < len(bulletins); i++ {
		b := decryptRSA(v.privateKey, bulletins[i])
		bulletins[i] = b
	}
	return nil
}

func (v *VoterActor) sendBulletinsNextVoter(bulletins BulletinList) {
	nextVoter := (v.selfIndexInChain + 1) % len(v.votersChain)
	v.send(bulletins, nextVoter)
}

func (v *VoterActor) send(bl BulletinList, voterChainIndex int) {
	sendData := BulletinListSending{bl, voterChainIndex}
	if voterChainIndex == v.selfIndexInChain {
		// new goroutine for deadlock prevention
		go func() {
			v.networkChannelInput <- sendData
		}()
	} else {
		v.networkChannelOutput <- sendData
	}
}

func (v *VoterActor) recv() (BulletinList, int) {
	recvData := <-v.networkChannelInput
	return recvData.Bulletins, recvData.VoterChainIndex
}

func (v *VoterActor) getBulletins3() (BulletinList, error) {
	for {
		bl, sender := v.recv()
		if sender == len(v.votersChain)-1 {
			if len(bl) != len(v.votersChain) {
				return nil, errors.New("bad bulletins count #3")
			} else {
				return bl, nil
			}
		}
	}
}

func (v *VoterActor) Vote(data []byte) error {
	bulletin, err := v.createBulletin(data)
	if err != nil {
		return err
	}

	// Send to first voter
	v.send(BulletinList{bulletin}, 0)

	// Get bulletins first time
	bulletins, err := v.getBulletins1()
	if err != nil {
		return err
	}

	// Decrypt bulletins first time (check our bulletin is in a list)
	err = v.decryptBulletins1(bulletins)
	if err != nil {
		return err
	}

	// Send Decrypted to next voter
	v.sendBulletinsNextVoter(bulletins)

	// Get bulletins second time
	bulletins, err = v.getBulletins2()
	if err != nil {
		return err
	}

	// verifying signature from previous voter
	// first voter only signing
	if v.selfIndexInChain != 0 {
		publicKey := v.votersChain[v.selfIndexInChain-1].PublicKey
		err = v.verifyBulletins(bulletins, &publicKey)
		for i := 0; i < len(v.votersChain); i++ {
			bulletins[i] = deleteSignature(bulletins[i])
		}
	}

	// Decrypt bulletins second time (and checks)
	fmt.Printf("%v decrypting2\n", v.selfIndexInChain)
	err = v.decryptBulletins2(bulletins)
	if err != nil {
		return err
	}

	//signing decrypted bulletins
	fmt.Printf("%v signing\n", v.selfIndexInChain)
	err = v.signBulletins(bulletins)

	if v.selfIndexInChain != len(v.votersChain)-1 {
		v.sendBulletinsNextVoter(bulletins)
		bulletins, err = v.getBulletins3()
		if err != nil {
			return err
		}
	} else {
		// Last voter sends results for each voter
		for i := 0; i < len(v.votersChain)-1; i++ {
			v.send(bulletins, i)
		}
	}
	//check bull signs received from last voter
	publicKey := v.votersChain[len(v.votersChain)-1].PublicKey
	err = v.verifyBulletins(bulletins, &publicKey)
	if err != nil {
		return err
	}
	//delete sign of last voter
	bulletins[v.selfIndexInChain] = deleteSignature(bulletins[v.selfIndexInChain])

	fmt.Printf("%v RESULT %v\n", v.selfIndexInChain, bulletins)
	return nil
}
