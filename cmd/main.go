package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	. "izbernet/pkg/izbernet"
)

func main() {
	voterCnt := 50
	voting := Voting{}

	input := make([]chan BulletinListSending, voterCnt)
	output := make([]chan BulletinListSending, voterCnt)

	V := make([]*VoterActor, voterCnt)

	keys := make([]*rsa.PrivateKey, voterCnt)
	for i := 0; i < voterCnt; i++ {
		keys[i], _ = rsa.GenerateKey(rand.Reader, 2048)
		voting.Voters = append(voting.Voters, Voter{Address: "", PublicKey: keys[i].PublicKey})
	}

	for i := 0; i < voterCnt; i++ {
		input[i] = make(chan BulletinListSending)
		output[i] = make(chan BulletinListSending)

		V[i], _ = NewVoterActor(voting, keys[i], output[i], input[i])
	}

	for i := 0; i < voterCnt; i++ {
		go func(i int) {
			err := V[i].Vote([]byte{1, 2, 3, 4})
			fmt.Printf("Voter %v done, err: %v\n", i, err)
		}(i)
		go func(i int) {
			for {
				msg := <-output[i]
				j := msg.VoterChainIndex
				input[j] <- BulletinListSending{Bulletins: msg.Bulletins, VoterChainIndex: i}
				fmt.Printf("\t\t%v -> %v\n", i, j)
			}
		}(i)
	}

	for {
	}
}
