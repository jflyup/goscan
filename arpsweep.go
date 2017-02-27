package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	//"github.com/hashicorp/mdns"
	"sync"
	"time"
)

var liveHosts map[string][]byte
var mutex = &sync.Mutex{}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	liveHosts = make(map[string][]byte)
	// Get a list of all interfaces.
	//ifaces, err := net.Interfaces()
	//if err != nil {
	//	panic(err)
	//}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	// Make a channel for results and start listening
	//	entriesCh := make(chan *mdns.ServiceEntry, 4)
	//	go func() {
	//		for entry := range entriesCh {
	//			log.Printf("Got new entry: %v\n", entry)
	//		}
	//	}()
	//
	//	// Start the lookup
	//	mdns.Lookup("_foobar._tcp", entriesCh)
	//	close(entriesCh)

	var wg sync.WaitGroup
	for _, iface := range devices {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface pcap.Interface) {
			defer wg.Done()
			if err := scan(&iface); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			}
		}(iface)
	}
	// Wait for all interfaces' scans to complete.  They'll try to run
	// forever, but will stop on an error, so if we get past this Wait
	// it means all attempts to write have failed.
	wg.Wait()
}

// scan scans an individual interface's local network for machines using ARP requests/replies.
//
// scan loops forever, sending packets out regularly.  It returns an error if
// it's ever unable to write a packet.
func scan(iface *pcap.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if iface.Addresses != nil {
		for _, a := range iface.Addresses {
			if ip4 := a.IP.To4(); ip4 != nil {
				addr = &net.IPNet{
					IP:   ip4,
					Mask: a.Netmask[len(a.Netmask)-4:],
				}
				break
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

	// use net.Interfaces() to get local mac adddress
	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var mac net.HardwareAddr
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ipnet.String() == addr.String() {
					log.Printf("got mac: %v", i.HardwareAddr)
					mac = i.HardwareAddr
				}
			}
		}
	}

	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, mac, stop)
	if err := writeARP(handle, mac, addr); err != nil {
		log.Printf("error writing packets on %v: %v", iface.Name, err)
	}

	timer := time.NewTimer(time.Second * 30)
	<-timer.C
	close(stop)
	return nil
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, mac net.HardwareAddr, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			log.Printf("find %d hosts", len(liveHosts))
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if bytes.Equal(mac, arp.SourceHwAddress) {
				// This is a packet I sent.
				continue
			} else if arp.Operation == layers.ARPRequest {
				// got broadcast arp request, consider the source host is alive
				// TODO RWMutex?
				mutex.Lock()
				if _, ok := liveHosts[net.IP(arp.SourceProtAddress).String()]; ok {
					liveHosts[net.IP(arp.SourceProtAddress).String()] = arp.SourceHwAddress
				}
				mutex.Unlock()
				//log.Printf("got broadcast arp from %v", net.HardwareAddr(arp.SourceHwAddress))
				continue
			}
			mutex.Lock()
			if _, ok := liveHosts[net.IP(arp.SourceProtAddress).String()]; !ok || len(os.Args) > 1 {
				liveHosts[net.IP(arp.SourceProtAddress).String()] = arp.SourceHwAddress
				// Note:  we might get some packets here that aren't responses to ones we've sent,
				// if for example someone else sends US an ARP request.  Doesn't much matter, though...
				// all information is good information :)
				log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			}
			mutex.Unlock()

		}
	}
}

// writeARP writes an ARP request for each address on our local network to the
// pcap handle.
func writeARP(handle *pcap.Handle, mac net.HardwareAddr, addr *net.IPNet) error {
	// Set up all the layers' fields we can.
	eth := layers.Ethernet{
		SrcMAC:       mac,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   mac,
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}
	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	var count int

	if len(os.Args) > 1 {
		ip := net.ParseIP(os.Args[1])
		log.Printf("sending arp")
		arp.DstProtAddress = ip.To4()
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		// Ethernet requires that all packets be at least 60 bytes long,
		// 64 bytes if you include the Frame Check Sequence at the end
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	} else {
		// Send one packet for every address.
		for _, ip := range ips(addr) {
			mutex.Lock()
			if _, ok := liveHosts[ip.String()]; !ok && ip.String() != addr.IP.String() {
				arp.DstProtAddress = []byte(ip)
				gopacket.SerializeLayers(buf, opts, &eth, &arp)
				if err := handle.WritePacketData(buf.Bytes()); err != nil {
					return err
				}
				count++
			}
			mutex.Unlock()

			// mimic Fing
			if count == 100 {
				go writeARP(handle, mac, addr)
			}
			time.Sleep(time.Millisecond * 10)
		}
	}
	return nil
}

// ips is a simple and not very good method for getting all IPv4 addresses from a
// net.IPNet.  It returns all IPs it can over the channel it sends back, closing
// the channel when done.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))
		mask++
		num++
	}
	return
}
