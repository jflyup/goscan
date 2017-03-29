package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"

	"flag"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"sync"
	"sync/atomic"
	"time"
)

var liveHosts map[string][]byte
var hostnames map[string]string
var mutex = &sync.Mutex{}
var m1 = &sync.Mutex{}
var target = flag.String("t", "", "target")
var scanTime = flag.Int("T", 10, "scan time")
var interval = flag.Int("i", 10, "interval of arp request, in ms")
var ptrQuery = flag.Bool("r", false, "do reverse DNS lookup")
var stopped int32

func main() {
	resultFile := flag.String("o", "", "scan result file")
	flag.Parse()
	//log.SetFlags(log.LstdFlags | log.Lshortfile)
	liveHosts = make(map[string][]byte)
	hostnames = make(map[string]string)
	if len(*resultFile) != 0 {
		f, err := os.OpenFile(*resultFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
		if err != nil {
			log.Printf("can't open %s", resultFile)
			return
		}
		defer f.Close()
		log.SetOutput(f)
	}
	// Get a list of all interfaces.
	//ifaces, err := net.Interfaces()
	//if err != nil {
	//	panic(err)
	//}
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var wg sync.WaitGroup
	for _, iface := range devices {
		wg.Add(1)
		// Start up a scan on each interface.
		go func(iface pcap.Interface) {
			defer wg.Done()
			scan(&iface)
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
					localhost, _ := os.Hostname()
					log.Printf("localhost: %s, mac: %v", localhost, i.HardwareAddr)
					mac = i.HardwareAddr
					mutex.Lock()
					liveHosts[ipnet.IP.String()] = mac
					mutex.Unlock()
					break
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

	go writeARP(handle, mac, addr)
	// exit program after scanning for a while
	timer := time.NewTimer(time.Second * time.Duration(*scanTime))
	<-timer.C
	close(stop)

	atomic.StoreInt32(&stopped, 1)
	log.Printf("find %d hosts in %ds", len(liveHosts), *scanTime)
	for k, v := range liveHosts {
		if name, ok := hostnames[k]; ok {
			log.Printf("IP %s(%s) is at %v", k, name, net.HardwareAddr(v))
		} else {
			log.Printf("IP %s is at %v", k, net.HardwareAddr(v))
		}
	}
	log.Printf("end of scan\n")
	return nil
}

func queryMDNS(ip string) {
}

func queryHostname(ip string) {
	for {
		retries := 0
		hostname, err := net.LookupAddr(ip)
		if err != nil {
			retries++
			if retries >= 3 {
				log.Printf("no dns record for %s", ip)
				return
			}
		} else {
			m1.Lock()
			hostnames[ip] = hostname[0]
			m1.Unlock()
			return
		}
	}
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
				srcIP := net.IP(arp.SourceProtAddress).String()
				if _, ok := liveHosts[srcIP]; !ok {
					liveHosts[srcIP] = arp.SourceHwAddress
					// lookup hostname in another goroutine
					if *ptrQuery {
						go queryHostname(srcIP)
					}
				}
				mutex.Unlock()
				continue
			}

			mutex.Lock()
			srcIP := net.IP(arp.SourceProtAddress).String()
			if _, ok := liveHosts[srcIP]; !ok || len(*target) > 0 {
				liveHosts[srcIP] = arp.SourceHwAddress
				if *ptrQuery {
					go queryHostname(srcIP)
				}
				// Note:  we might get some packets here that aren't responses to ones we've sent,
				// if for example someone else sends US an ARP request.  Doesn't much matter, though...
				// all information is good information :)
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

	if len(*target) > 1 {
		ip := net.ParseIP(*target)
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
				if atomic.LoadInt32(&stopped) == 0 {
					if err := handle.WritePacketData(buf.Bytes()); err != nil {
						return err
					}
				}
				count++
			}
			mutex.Unlock()

			// mimic Fing's strategy
			if count == 100 {
				go writeARP(handle, mac, addr)
			}
			time.Sleep(time.Millisecond * time.Duration(*interval))
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
