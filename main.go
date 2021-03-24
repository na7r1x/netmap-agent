package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string = "en0"
	snapshot_len int32  = 10240
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 5 * time.Second
	handle       *pcap.Handle

	// packet decoder 'marshalling'
	ethLayer   layers.Ethernet
	ipLayer    layers.IPv4
	ip6Layer   layers.IPv6
	tcpLayer   layers.TCP
	udpLayer   layers.UDP
	srcIp      string
	dstIp      string
	srcPort    int
	dstPort    int
	packetType string
)

func main() {
	// Open device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&ip6Layer,
			&tcpLayer,
			&udpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				// fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				srcIp = ipLayer.SrcIP.String()
				dstIp = ipLayer.DstIP.String()
			}
			if layerType == layers.LayerTypeIPv6 {
				// fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
				srcIp = ip6Layer.SrcIP.String()
				dstIp = ip6Layer.DstIP.String()
			}
			if layerType == layers.LayerTypeTCP {
				// fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				// fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
				packetType = "TCP"
				srcPort = int(tcpLayer.SrcPort)
				dstPort = int(tcpLayer.DstPort)
			}
			if layerType == layers.LayerTypeUDP {
				packetType = "UDP"
				srcPort = int(udpLayer.SrcPort)
				dstPort = int(udpLayer.DstPort)
			}
		}

		fmt.Printf("[%s] %s:%d --> %s:%d\n", packetType, srcIp, srcPort, dstIp, dstPort)
	}
}
