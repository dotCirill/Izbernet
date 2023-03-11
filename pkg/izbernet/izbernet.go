package izbernet

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	insecureRand "math/rand"
)

type VoterPublicInfo struct {
	PublicKey int
}

type Bulletin int
type BulletinList []Bulletin
type BulletinListSending struct {
	Bulletins       BulletinList
	VoterChainIndex int
}

type Voter struct {
	SelfIndexInChain     int
	VotersChain          []VoterPublicInfo
	randoms              []int
	NetworkChannelOutput chan BulletinListSending
	NetworkChannelInput  chan BulletinListSending
}

func (v *Voter) createBulletin(data int) Bulletin {
	// TODO append random to data
	y := data
	for i := len(v.VotersChain) - 1; i >= 0; i-- {
		y = y ^ 1 // TODO Encrypt
	}

	for i := len(v.VotersChain) - 1; i >= 0; i-- {
		y = y ^ 1 // TODO Encrypt with random
	}

	return Bulletin(y)
}

func (v *Voter) decryptBulletins1(BulletinList) error {
	// TODO
	return nil
}

func (v *Voter) recvBulletinsPrevVoter() BulletinList {
	n := len(v.VotersChain)
	prevVoter := (n + v.SelfIndexInChain - 1) % n
	for {
		bl, voter := v.recv()
		if voter == prevVoter {
			return bl
		}
	}
}

func (v *Voter) getBulletins1() (BulletinList, error) {
	bulletins := make(BulletinList, len(v.VotersChain))

	if v.SelfIndexInChain == 0 {
		// get 1 bulletin from each users
		bulletinsCount := 0
		for bulletinsCount < len(v.VotersChain) {
			bl, voter := v.recv()
			if (len(bl) == 1) && bulletins[voter] == 0 {
				bulletins[voter] = bl[0]
				bulletinsCount++
			}
		}
	} else {
		// get all bulletin from prev user
		bulletins = v.recvBulletinsPrevVoter()
	}

	if len(bulletins) != len(v.VotersChain) {
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

func (v *Voter) getBulletins2() (BulletinList, error) {
	bl := v.recvBulletinsPrevVoter()
	if len(bl) != len(v.VotersChain) {
		return nil, errors.New("bad bulletins count #2")
	}

	return bl, nil
}

func (v *Voter) decryptBulletins2(BulletinList) error {
	// TODO
	return nil
}

func (v *Voter) sendBulletinsNextVoter(bulletins BulletinList) {
	nextVoter := (v.SelfIndexInChain + 1) % len(v.VotersChain)
	v.send(bulletins, nextVoter)
}

func (v *Voter) send(bl BulletinList, voterChainIndex int) {
	sendData := BulletinListSending{bl, voterChainIndex}
	if voterChainIndex == v.SelfIndexInChain {
		// new goroutine for deadlock prevention
		go func() {
			v.NetworkChannelInput <- sendData
		}()
	} else {
		v.NetworkChannelOutput <- sendData
	}
}

func (v *Voter) recv() (BulletinList, int) {
	recvData := <-v.NetworkChannelInput
	return recvData.Bulletins, recvData.VoterChainIndex
}

func (v *Voter) getBulletins3() (BulletinList, error) {
	for {
		bl, sender := v.recv()
		if sender == len(v.VotersChain)-1 {
			if len(bl) != len(v.VotersChain) {
				return nil, errors.New("bad bulletins count #3")
			} else {
				return bl, nil
			}
		}
	}
}

func (v *Voter) Vote(data int) error {
	bulletin := v.createBulletin(data)

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

	// Decrypt bulletins first time (and checks)
	err = v.decryptBulletins2(bulletins)
	if err != nil {
		return err
	}

	if v.SelfIndexInChain != len(v.VotersChain)-1 {
		v.sendBulletinsNextVoter(bulletins)
		bulletins, err = v.getBulletins3()
		if err != nil {
			return err
		}
	} else {
		// Last voter sends results for each voter
		for i := 0; i < len(v.VotersChain)-1; i++ {
			v.send(bulletins, i)
		}
	}

	result := 0
	for i := 0; i < len(bulletins); i++ {
		result += int(bulletins[i])
	}

	fmt.Printf("%v RESULT %v\n", v.SelfIndexInChain, result)
	return nil
}
