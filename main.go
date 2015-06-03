package main

import (
    "code.google.com/p/gopacket/pcap"
    "fmt"
)

func main(){
      if handle, err := pcap.OpenOffline("/path/to/my/file"); err != nil {
      panic(err)
    } else {
  packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
  for packet := range packetSource.Packets() {
    handlePacket(packet)  // Do something with a packet here.
  }
}

}
