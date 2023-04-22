package main

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/gologme/log"
	"golang.org/x/net/ipv6"

	"github.com/yggdrasil-network/yggdrasil-go/src/core"
	"github.com/yggdrasil-network/yggdrasil-go/src/ipv6rwc"
)

type DataAddress struct {
	data    []byte
	address []byte
}

func recv(yggRwc *ipv6rwc.ReadWriteCloser, chDataAddress chan DataAddress) {
	ipv6Bytes := make([]byte, yggRwc.MTU())

	for {
		n, err := yggRwc.Read(ipv6Bytes)
		if err != nil {
			panic(err)
		}

		fmt.Printf("AAAAAAAAAAAAAAAAaaAAaAAAaAAAAAAAA\n")

		if n < 40 {
			continue // not a IPv6
		}

		dataAddress := DataAddress{data: ipv6Bytes[40:], address: ipv6Bytes[8:24]}
		chDataAddress <- dataAddress
	}
}

func ipv6Header_Marshal(h *ipv6.Header) []byte {
	b := make([]byte, 40)
	b[0] |= byte(h.Version) << 4
	b[0] |= byte(h.TrafficClass) >> 4
	b[1] |= byte(h.TrafficClass) << 4
	b[1] |= byte(h.FlowLabel >> 16)
	b[2] = byte(h.FlowLabel >> 8)
	b[3] = byte(h.FlowLabel)
	binary.BigEndian.PutUint16(b[4:6], uint16(h.PayloadLen))
	b[6] = byte(h.NextHeader)
	b[7] = byte(h.HopLimit)
	copy(b[8:24], h.Src)
	copy(b[24:40], h.Dst)
	return b
}

func send(yggRwc *ipv6rwc.ReadWriteCloser, chDataAddress chan DataAddress) {
	myIp := yggRwc.Address()
	for {
		DataAddress := <-chDataAddress
		ipv6Header := ipv6.Header{
			Version:    ipv6.Version,
			FlowLabel:  0xdead,
			NextHeader: 58,
			PayloadLen: len(DataAddress.data),
			HopLimit:   255,
			Src:        myIp[:],
			Dst:        DataAddress.address,
		}

		ipv6Packet := ipv6Header_Marshal(&ipv6Header)
		ipv6Packet = append(ipv6Packet, DataAddress.data...)

		_, err := yggRwc.Write(ipv6Packet[:])
		if err != nil {
			panic(err)
		}

		fmt.Printf("AAAAAAA\n")

	}
}

func main() {
	logger := log.New(os.Stdout, "[Yggdrasil] ", log.Flags())

	options := []core.SetupOption{}

	var nodeInfo core.NodeInfo // empty
	options = append(options, nodeInfo)

	options = append(options, core.NodeInfoPrivacy(true))

	options = append(options, core.Peer{URI: "tcp://itcom.multed.com:7991"})
	// todo allowed public keys

	keysRecv := genKey()
	keysSend := genKey()
	yggCoreRecv, _ := core.New(keysRecv.priv, logger, options...)
	yggCoreSend, err := core.New(keysSend.priv, logger, options...)

	fmt.Printf("Recv: %v\n ", yggCoreRecv.Address())

	if err != nil {
		panic(err)
	}

	yggRwc1 := ipv6rwc.NewReadWriteCloser(yggCoreRecv)
	yggRwc1.SetMTU(yggRwc1.MaxMTU())

	yggRwc2 := ipv6rwc.NewReadWriteCloser(yggCoreSend)
	yggRwc2.SetMTU(yggRwc2.MaxMTU())

	ch1 := make(chan DataAddress)
	ch2 := make(chan DataAddress)

	go recv(yggRwc1, ch1)
	go send(yggRwc2, ch2)

	go recv(yggRwc2, ch2)
	go func() {
		address := yggRwc1.Address()
		time.Sleep(time.Second * 5)
		ch1 <- DataAddress{data: []byte{123, 123}, address: address[:]}
	}()

	send(yggRwc1, ch1)
}

type keySet struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func genKey() keySet {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	return keySet{priv, pub}
}
