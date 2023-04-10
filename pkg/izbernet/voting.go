package izbernet

import (
	"crypto/rsa"
)

type Voting struct {
	Question string
	Answers  []string
	Voters   []Voter
}

type Voter struct {
	PublicKey rsa.PublicKey
	Address   string
}
