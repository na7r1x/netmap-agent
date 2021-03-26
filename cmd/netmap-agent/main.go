package main

import (
	"github.com/na7r1x/netmap-agent/internal/services/dispatchersrv"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
	"flag"
	"context"
	"sync"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/na7r1x/netmap-agent/internal/domain"
	"github.com/na7r1x/netmap-agent/internal/services/aggregatorsrv"
)

var (
	netInterface       string
	snapshot_len int32 = 10240
	promiscuous  bool  = false
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

	// bastion config
	bastionUrl string
)

func init() {
	flag.StringVar(&netInterface, "interface", "", "A network interface to monitor.")	
	flag.StringVar(&bastionUrl, "bastion", "", "A bastion address, to which metrics will be pushed.")

	flag.Parse()

	if (netInterface == "") {
		fmt.Println("No device selected; will listen on all interfaces")
	} else {
		fmt.Println("Selected device: " + netInterface)
	}

	if (bastionUrl == "") {
		fmt.Println("Bastion url is required.")
	} else {
		fmt.Println("Will publish metrics to:  " + bastionUrl)
	}
}

func main() {
	// channel used to signal termination
	stop := make(chan struct{})
	defer close(stop)

	// pipeline channels
	aggrIn := make(chan domain.PacketEnvelope)     // to aggregator
	dispatcherIn := make(chan domain.TrafficGraph) // from aggregator to dispatcher (sink)

	// Set up cancellation context and waitgroup
	ctx, cancelFunc := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	// initialise aggregator in a separate goroutine
	aggr := aggregatorsrv.New(aggrIn, dispatcherIn, ctx)
	wg.Add(1)
	go aggr.Listen(wg)
	
	// initialise dispatcher in a separate goroutine
	dispatcher := dispatchersrv.New("http://localhost", bastionUrl, dispatcherIn, ctx)
	dispatcher.Connect()
	wg.Add(1)
	go dispatcher.Listen(wg)


	// Get a list of all interfaces.
	var ifaces []net.Interface
	if (netInterface != "") {
		thisInterface, err := net.InterfaceByName(netInterface)
		if (err != nil) {
			fmt.Println("Failed fetching interface: " + err.Error())
			panic(err)
		}
		ifaces = append(ifaces, *thisInterface)
	} else {
		ifaces, err = net.Interfaces()
		if err != nil {
			panic(err)
		}
	}

	// Get a list of all devices if not specified
	devices, err := pcap.FindAllDevs()
	if err != nil {
		panic(err)
	}

	for _, iface := range ifaces {
		// Start up a scan on each interface.
		wg.Add(1)
		go func(iface net.Interface) {
			defer wg.Done()
			thisDevice, err := resolveDevice(&iface, &devices)
			if err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			} else {
				fmt.Println("Start monitoring packets on device: " + thisDevice)
				monitorPackets(thisDevice, ctx, aggrIn)
			}
		}(iface)
	}

	// start periodic flushing
	wg.Add(1)
	go func(ctx context.Context, wg *sync.WaitGroup) {
		defer wg.Done()
		select{
		case <- ctx.Done():
			fmt.Println("Flushing routine received termination signal - shutting down.")
			return
		default:
			time.Sleep(10 * time.Second)
			aggr.Flush()
		}
	}(ctx,wg)

	// Handle sigterm and await termChan signal
	termChan := make(chan os.Signal)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)
	
	<-termChan         // Blocks here until interrupted

	// Handle shutdown
	fmt.Println("*********************************\nShutdown signal received\n*********************************")
	cancelFunc()       // Signal cancellation to context.Context
	wg.Wait()          // Block here until are workers are done
	
	fmt.Println("All workers done, shutting down!")
	
}




func resolveDevice(iface *net.Interface, devices *[]pcap.Interface) (string, error) {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return "", err
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
		return "", errors.New("no good IP network found")
	} else if addr.IP[0] == 127 {
		return "", errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return "", errors.New("mask means network is too large")
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
		return "", fmt.Errorf("Cannot find the corresponding device for the interface %s", iface.Name)
	} else {
		return deviceName, nil
	}
}

func monitorPackets(thisDevice string, ctx context.Context, aggrIn chan domain.PacketEnvelope) {
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
		case <-ctx.Done():
			fmt.Printf("stopping packet monitoring for: %s", thisDevice)
			return
		case packet = <-in:
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
				// fmt.Println("Trouble decoding layers: ", err)
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

			// fmt.Printf("[%s] %s:%d --> %s:%d\n", packetType, srcIp, srcPort, dstIp, dstPort)
			toAggregate := domain.PacketEnvelope{
				Type:    packetType,
				SrcAddr: srcIp,
				SrcPort: srcPort,
				DstAddr: dstIp,
				DstPort: dstPort,
			}
			aggrIn <- toAggregate
		}
	}
}
