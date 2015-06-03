package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"fmt"
)

func main() {
	if handle, err := pcap.OpenOffline("/path/to/file.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if packet == nil {
				fmt.Println("empty packet")
			} else if packet.TransportLayer() == nil {
				fmt.Println("no transport")
			} else {
				link := packet.LinkLayer()
				linkFlow := link.LinkFlow()
				net := packet.NetworkLayer()
				netFlow := net.NetworkFlow()
				trans := packet.TransportLayer()
				transFlow := trans.TransportFlow()
				//	app := packet.ApplicationLayer()
				fmt.Println(linkFlow, netFlow, transFlow, packet.Metadata().Timestamp)
				//	fmt.Println(app)
			}
		}

	}

}
