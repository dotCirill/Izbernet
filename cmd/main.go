package main

import (
	"fmt"
	. "izbernet/pkg/izbernet"
)

func main() {
	voterCnt := 40

	vchain := make([]VoterPublicInfo, voterCnt)
	input := make([]chan BulletinListSending, voterCnt)
	output := make([]chan BulletinListSending, voterCnt)

	for i := 0; i < voterCnt; i++ {
		vchain[i] = VoterPublicInfo{i}
		input[i] = make(chan BulletinListSending)
		output[i] = make(chan BulletinListSending)
	}

	V := make([]Voter, voterCnt)
	for i := 0; i < voterCnt; i++ {
		V[i] = Voter{
			SelfIndexInChain:     i,
			VotersChain:          vchain,
			NetworkChannelOutput: output[i],
			NetworkChannelInput:  input[i],
		}
	}

	for i := 0; i < voterCnt; i++ {
		go V[i].Vote(i + 123)
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
