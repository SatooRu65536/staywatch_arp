package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	selectedIface string
)

func init() {
	flag.StringVar(&selectedIface, "i", "en0", "select wifi iface")
}

func main() {
	flag.Parse()

	ifaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	for _, iface := range ifaces {
		if iface.Name != selectedIface {
			continue
		}

		wg.Add(1)

		go func(iface net.Interface) {
			defer wg.Done()
			if err, macs := scan(&iface); err != nil {
				log.Printf("interface %v: %v", iface.Name, err)
			} else {
				log.Printf("interface %v: %v", iface.Name, macs)
				sendApiRequest(macs)
			}
		}(iface)
	}

	wg.Wait()
}

func scan(iface *net.Interface) (error, []net.HardwareAddr) {
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err, nil
	} else {
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			ip4 := ipnet.IP.To4()
			if ip4 == nil {
				continue
			}
			addr = &net.IPNet{
				IP:   ip4,
				Mask: ipnet.Mask[len(ipnet.Mask)-4:],
			}
			break
		}
	}

	if addr == nil {
		return errors.New("no good IP network found"), nil
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost"), nil
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask means network is too large"), nil
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err, nil
	}
	defer handle.Close()

	stop := make(chan struct{})
	macAddresses := make(chan []net.HardwareAddr)
	go readARP(handle, iface, stop, macAddresses)
	defer close(macAddresses)
	writeARP(handle, iface, addr)
	time.Sleep(2 * time.Second)
	close(stop)
	macs := <-macAddresses

	return nil, macs
}

func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}, macAddresses chan []net.HardwareAddr) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	var macs []net.HardwareAddr

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			macAddresses <- macs
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply || bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress) {
				continue
			}
			log.Printf("IP %v is at %v", net.IP(arp.SourceProtAddress), net.HardwareAddr(arp.SourceHwAddress))
			macs = append(macs, net.HardwareAddr(arp.SourceHwAddress))
		}
	}
}

func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet) error {

	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	for _, ip := range ips(addr) {
		arp.DstProtAddress = []byte(ip)
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	network := num & mask
	broadcast := network | ^mask
	for network++; network < broadcast; network++ {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], network)
		out = append(out, net.IP(buf[:]))
	}
	return
}

type RequestBody struct {
	MACAddresses []string `json:"MACAddresses"`
}

func sendApiRequest(macAddresses []net.HardwareAddr) {
	// string[] に変換
	var macsStr []string
	for _, mac := range macAddresses {
		macsStr = append(macsStr, mac.String())
	}

	// リクエストボディを作成
	requestBody := RequestBody{
		MACAddresses: macsStr,
	}
	jsonStr, err := json.Marshal(requestBody)
	if err != nil {
		log.Printf("Failed to marshal json: %v", err)
		return
	}

	log.Printf("Request body: %v", string(jsonStr))

	endpoint := "https://sysken-stay-watch-api.sysken.net/api/register/set"
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Printf("Failed to create request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	client := new(http.Client)
	res, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to send request: %v", err)
		return
	}
	defer res.Body.Close()

	bytes, err := io.ReadAll(res.Body)
	if err != nil {
		log.Printf("Failed to read response: %v", err)
		return
	}

	fmt.Println(string(bytes))
}
