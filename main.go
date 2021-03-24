package main

import (
	"fmt"
	"log"
	"time"
	"net"
	"errors"
	"sync"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	device       string
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

// func init() {
// 	flag.StringVar(&device, "netInterface", "eth0", "A network interface to monitor.")
// 	fmt.Println("selected device " + device)
// 	ifaces, err := net.Interfaces()
//     if err != nil {
//         fmt.Print(fmt.Errorf("localAddresses: %+v\n", err.Error()))
//         return
//     }
// 	fmt.Println(ifaces)
// }

func main() {
	// Get a list of all interfaces.
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	// Get a list of all devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface net.Interface) {
			defer wg.Done()
			if err := scan(&iface, &devices); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
	}
	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

func scan(iface *net.Interface, devices *[]pcap.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large")
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	// Try to find a match between device and interface
	var deviceName string
	for _, d := range *devices {
		if strings.Contains(fmt.Sprint(d.Addresses), fmt.Sprint(addr.IP)) {
			deviceName = d.Name
		}
	}

	if deviceName == "" {
		return fmt.Errorf("Cannot find the corresponding device for the interface %s", iface.Name)
	} else {
		fmt.Println("Start monitoring packets on device: " + deviceName)
		stop := make(chan struct{})
		go monitorPackets(deviceName)
		defer close(stop)
	}

	return nil
}

func monitorPackets(thisDevice string) {
	// Open device
	handle, err = pcap.OpenLive(thisDevice, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	in := packetSource.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <- stop:
			return
		case packet = <- in:
			
		}
	}
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
