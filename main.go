package main

import (
	"code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"strings"
	"time"
)

type ipv4 struct {
	version     string
	ihl         string
	tos         string
	ipLenth     string
	id          string
	flags       string
	flagOffset  string
	ttl         string
	protocol    string
	checksum    string
	source      string
	destination string
	//options     string
	//padding     string
}

type ipv6 struct {
	version      string
	trafficClass string
	flowLabel    string
	ipLenth      string
	nextHeader   string
	hopLimit     string
	sourceIP     string
	destIP       string
	hopByHop     string
}

type tcp struct {
	sourcePort    string
	destPort      string
	seq           string
	ackNumber     string
	dataOffset    string
	fin           string
	syn           string
	rst           string
	psh           string
	ack           string
	urg           string
	ece           string
	cwr           string
	ns            string
	window        string
	tcpChecksum   string
	urgentPointer string
	//	tcpOptions    string
	//	tcpPadding    string
}

type udp struct {
	sourcePort  string
	destPort    string
	udpLength   string
	udpChecksum string
}

type linkLayer struct {
	protocol    string
	source      string
	destination string
	ethertype   string
	length      string
}

type networkLayer struct {
	protocol string
	four     *ipv4
	six      *ipv6
}

type transportLayer struct {
	protocol string
	tee      *tcp
	yoo      *udp
}

type fullPacket struct {
	length      int
	timestamp   time.Time
	truncated   bool
	link        *linkLayer
	network     *networkLayer
	transport   *transportLayer
	application []byte
}

func insertMongoDB(session *mgo.Session, packet fullPacket) error {
	var packetLenght int
	var packetTimestamp time.Time
	var packetTruncated bool
	var linkProtocol string
	var linkSource string
	var linkDestination string
	var linkEthertype string
	var linkLength string
	var networkProtocol string


	packetLenght = packet.length
	packetTimestamp = packet.timestamp
	packetTruncated = packet.truncated

	collection := session.DB("pcap").C("master")

	if packet.link != nil {
		linkProtocol = packet.link.protocol
		linkSource = packet.link.source
		linkDestination = packet.link.destination
		linkEthertype = packet.link.ethertype
		linkLength = packet.link.length
	}

	query := bson.M{
		"l":  packetLenght,
		"ts": packetTimestamp,
		"tr": packetTruncated,
		"ll": bson.M{"p": linkProtocol, "s": linkSource, "d": linkDestination, "e": linkEthertype, "l": linkLength},
		"nl": bson.M{"p:" network}
	}
	err := collection.Insert(query)
	return err

}

func createTCP(transFields []string) *tcp {
	tee := tcp{
		strings.Split(transFields[3], "=")[1],
		strings.Split(transFields[4], "=")[1],
		strings.Split(transFields[5], "=")[1],
		strings.Split(transFields[6], "=")[1],
		strings.Split(transFields[7], "=")[1],
		strings.Split(transFields[8], "=")[1],
		strings.Split(transFields[9], "=")[1],
		strings.Split(transFields[10], "=")[1],
		strings.Split(transFields[11], "=")[1],
		strings.Split(transFields[12], "=")[1],
		strings.Split(transFields[13], "=")[1],
		strings.Split(transFields[14], "=")[1],
		strings.Split(transFields[15], "=")[1],
		strings.Split(transFields[16], "=")[1],
		strings.Split(transFields[17], "=")[1],
		strings.Split(transFields[18], "=")[1],
		strings.Split(transFields[19], "=")[1],
		//	strings.Split(transFields[20], "=")[1],
		//	strings.Trim(strings.Split(transFields[21], "=")[1], "}"),
	}
	return &tee
}

func createUDP(transFields []string) *udp {
	yoo := udp{
		strings.Split(transFields[3], "=")[1],
		strings.Split(transFields[4], "=")[1],
		strings.Split(transFields[5], "=")[1],
		strings.Trim(strings.Split(transFields[6], "=")[1], "}"),
	}
	return &yoo
}

func createFour(netFields []string) *ipv4 {
	four := ipv4{
		strings.Split(netFields[3], "=")[1],
		strings.Split(netFields[4], "=")[1],
		strings.Split(netFields[5], "=")[1],
		strings.Split(netFields[6], "=")[1],
		strings.Split(netFields[7], "=")[1],
		strings.Split(netFields[8], "=")[1],
		strings.Split(netFields[9], "=")[1],
		strings.Split(netFields[10], "=")[1],
		strings.Split(netFields[11], "=")[1],
		strings.Split(netFields[12], "=")[1],
		strings.Split(netFields[13], "=")[1],
		strings.Split(netFields[14], "=")[1],
		//	strings.Split(netFields[15], "=")[1],
		//	strings.Trim(strings.Split(netFields[16], "=")[1], "}"),
	}
	return &four
}

func createSix(netFields []string) *ipv6 {
	six := ipv6{
		strings.Split(netFields[3], "=")[1],
		strings.Split(netFields[4], "=")[1],
		strings.Split(netFields[5], "=")[1],
		strings.Split(netFields[6], "=")[1],
		strings.Split(netFields[7], "=")[1],
		strings.Split(netFields[8], "=")[1],
		strings.Split(netFields[9], "=")[1],
		strings.Split(netFields[10], "=")[1],
		strings.Trim(strings.Split(netFields[11], "=")[1], "}"),
	}
	return &six
}

func createLinkLayer(link gopacket.LinkLayer) *linkLayer {
	linkString := gopacket.LayerString(link)
	linkFields := strings.Fields(linkString)
	linkFinal := linkLayer{
		linkFields[0],
		strings.Split(linkFields[3], "=")[1],
		strings.Split(linkFields[4], "=")[1],
		strings.Split(linkFields[5], "=")[1],
		strings.Trim(strings.Split(linkFields[6], "=")[1], "}"),
	}
	return &linkFinal
}

func createNetworkLayer(net gopacket.NetworkLayer) *networkLayer {
	var four *ipv4
	var six *ipv6

	four = nil
	six = nil

	netString := gopacket.LayerString(net)
	netFields := strings.Fields(netString)

	if netFields[0] == "IPv4" {
		four = createFour(netFields)
	} else {
		six = createSix(netFields)
	}

	netFinal := networkLayer{
		netFields[0],
		four,
		six,
	}

	return &netFinal
}

func createTransportLayer(trans gopacket.TransportLayer) *transportLayer {
	var tee *tcp
	var yoo *udp

	tee = nil
	yoo = nil

	transString := gopacket.LayerString(trans)
	transFields := strings.Fields(transString)

	if transFields[0] == "TCP" {
		tee = createTCP(transFields)
	} else {
		yoo = createUDP(transFields)
	}

	transFinal := transportLayer{
		transFields[0],
		tee,
		yoo,
	}

	return &transFinal
}

func createPacket(packet gopacket.Packet) fullPacket {
	var link *linkLayer
	var net *networkLayer
	var trans *transportLayer
	var app []byte

	link = nil
	net = nil
	trans = nil
	app = nil

	if packet.LinkLayer() != nil {
		link = createLinkLayer(packet.LinkLayer())
	}

	if packet.NetworkLayer() != nil {
		net = createNetworkLayer(packet.NetworkLayer())
	}

	if packet.TransportLayer() != nil {
		trans = createTransportLayer(packet.TransportLayer())
	}
	if packet.ApplicationLayer() != nil {
		app = packet.ApplicationLayer().Payload()
	}

	packetFinal := fullPacket{
		packet.Metadata().Length,
		packet.Metadata().Timestamp,
		packet.Metadata().Truncated,
		link,
		net,
		trans,
		app,
	}

	return packetFinal
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
		session, err := mgo.Dial("localhost:27017")
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			pack := createPacket(packet)
			if err == nil {
				insertMongoDB(session, pack)
			}
		}
	}
}
