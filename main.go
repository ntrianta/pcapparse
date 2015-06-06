package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

func ipFlow(packet gopacket.Packet, s *mgo.Session) error {

	err := error(nil)
	c := s.DB("pcap").C("IP")
	net := packet.NetworkLayer()
	netFlow := net.NetworkFlow()
	src, dst := netFlow.Endpoints()
	flow := bson.M{
		"s": src.String(),
		"p": dst.String(),
	}
	err = c.Insert(flow)

	return err
}

func main() {
	//Pcap file is given as a possitional argument, will be totally changed!
	flag.Parse()
	args := flag.Args()

	dir := args[0]

	handle, err := pcap.OpenOffline(dir)

	if err != nil {
		panic(err)
	} else {
		s, _ := mgo.Dial("localhost:27017")

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if packet.NetworkLayer() != nil {
				_ = ipFlow(packet, s)
			}
		}
		s.Close()

	}
}
