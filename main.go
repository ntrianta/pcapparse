package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"fmt"
)

func main() {
	if handle, err := pcap.OpenOffline("/path/to/file"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {

			fmt.Println(packet)
		}

	}

}
