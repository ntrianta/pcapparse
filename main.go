package main

import (
	"code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"fmt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"path/filepath"
	"strings"
	"time"
)

type ipv4 struct {
	version     string
	ihl         string
	tos         string
	ipLength    string
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
	source        string
	dest          string
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

	var mongoLinkLayer bson.M
	var mongoNetworkLayer bson.M
	var mongoTransportLayer bson.M

	packetLenght := packet.length
	packetTimestamp := packet.timestamp
	packetTruncated := packet.truncated
	packetPayload := packet.application

	collection := session.DB("pcap").C("master")

	if packet.link != nil {
		linkProtocol := packet.link.protocol
		linkSource := packet.link.source
		linkDestination := packet.link.destination
		linkEthertype := packet.link.ethertype
		linkLength := packet.link.length
		mongoLinkLayer = bson.M{"p": linkProtocol, "s": linkSource, "d": linkDestination,
			"e": linkEthertype, "l": linkLength}
	}
	if packet.network != nil {
		networkProtocol := packet.network.protocol
		if packet.network.four != nil {
			networkVersion := packet.network.four.version
			networkIHL := packet.network.four.ihl
			networkTOS := packet.network.four.tos
			networkLength := packet.network.four.ipLength
			networkID := packet.network.four.id
			networkFlags := packet.network.four.flags
			networkFlagOffset := packet.network.four.flagOffset
			networkTTL := packet.network.four.ttl
			networkTransProtocol := packet.network.four.protocol
			networkChecksum := packet.network.four.checksum
			networkSource := packet.network.four.source
			networkDestination := packet.network.four.destination
			mongoNetworkLayer = bson.M{"p": networkProtocol, "v": networkVersion, "ihl": networkIHL,
				"tos": networkTOS, "l": networkLength, "id": networkID,
				"f": networkFlags, "fo": networkFlagOffset, "ttl": networkTTL,
				"tp": networkTransProtocol, "c": networkChecksum,
				"s": networkSource, "d": networkDestination}
		} else {
			networkVersion := packet.network.six.version
			networkTrafficClass := packet.network.six.trafficClass
			networkFlowLabel := packet.network.six.flowLabel
			networkNextHeader := packet.network.six.nextHeader
			networkHopLimit := packet.network.six.hopLimit
			networkSource := packet.network.six.sourceIP
			networkDestination := packet.network.six.destIP
			networkHopByHop := packet.network.six.hopByHop
			mongoNetworkLayer = bson.M{"p": networkProtocol, "v": networkVersion,
				"tc": networkTrafficClass, "fl": networkFlowLabel,
				"nh": networkNextHeader, "hl": networkHopLimit, "hbh": networkHopByHop,
				"s": networkSource, "d": networkDestination}
		}
	}
	if packet.transport != nil {
		transportProtocol := packet.transport.protocol
		if packet.transport.tee != nil {
			transportSource := packet.transport.tee.source
			transportDestination := packet.transport.tee.dest
			transportSeq := packet.transport.tee.seq
			transportAckNumber := packet.transport.tee.ackNumber
			transportDataOffset := packet.transport.tee.dataOffset
			transportFin := packet.transport.tee.fin
			transportSyn := packet.transport.tee.syn
			transportRst := packet.transport.tee.rst
			transportPsh := packet.transport.tee.psh
			transportAck := packet.transport.tee.ack
			transportUrg := packet.transport.tee.urg
			transportEce := packet.transport.tee.ece
			transportCwr := packet.transport.tee.cwr
			transportNs := packet.transport.tee.ns
			transportWindow := packet.transport.tee.window
			transportChecksum := packet.transport.tee.tcpChecksum
			transportUrgentPointer := packet.transport.tee.urgentPointer
			mongoTransportLayer = bson.M{"p": transportProtocol, "s": transportSource,
				"d": transportDestination, "seq": transportSeq, "an": transportAckNumber,
				"do": transportDataOffset, "fin": transportFin, "syn": transportSyn,
				"rst": transportRst, "phs": transportPsh, "ack": transportAck,
				"urg": transportUrg, "ece": transportEce, "cwr": transportCwr,
				"ns": transportNs, "w": transportWindow, "cs": transportChecksum,
				"up": transportUrgentPointer,
			}
		} else {
			transportSource := packet.transport.yoo.sourcePort
			transportDestination := packet.transport.yoo.destPort
			transportLength := packet.transport.yoo.udpLength
			transportChecksum := packet.transport.yoo.udpChecksum
			mongoTransportLayer = bson.M{"p": transportProtocol, "s": transportSource,
				"d": transportDestination, "l": transportLength, "cs": transportChecksum,
			}
		}
	}

	query := bson.M{
		"l":  packetLenght,
		"ts": packetTimestamp,
		"tr": packetTruncated,
		"ll": mongoLinkLayer,
		"nl": mongoNetworkLayer,
		"tl": mongoTransportLayer,
		"al": packetPayload,
	}
	err := collection.Insert(query)
	return err
}

func createTCP(transFields []string) *tcp {
	var tee tcp
	if len(transFields) == 22 {
		tee = tcp{
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
	} else {
		tee = tcp{
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
			"ignore",
		}
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
	files, _ := filepath.Glob(dir + "/*")
	for _, file := range files {
		handle, err := pcap.OpenOffline(file)
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
			session.Close()
		}
	   fmt.Println("finished", file)
	}
}
