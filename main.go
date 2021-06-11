package main

import (
	"bytes"
	"fmt"
	"net/http"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"time"
	"io/ioutil"
	"strconv"
	"encoding/hex"

	"gopkg.in/yaml.v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var link_type layers.LinkType
var port_service_map map[string]string 
type Packet struct {
	Outgoing bool
	Payload_str string
	Payload_hex string
	Direction   string
}

func write_pcap(filename string, packets_flow []gopacket.Packet) {
	f, err := os.Create(filepath.Join("dumps", filename))
	if err != nil {
		fmt.Printf("failed to create pcap file at %s: %v\n", filename, err)
	}
	pcapw := pcapgo.NewWriter(f)
	if err := pcapw.WriteFileHeader(65536, link_type); err != nil {
		fmt.Printf("failed to write file header: %v\n", err)
	}
	for _, p := range packets_flow {
		pcapw.WritePacket(p.Metadata().CaptureInfo, p.Data())
	}
}

func list_pcaps(cose string) (map[string]string) {
	files, err := ioutil.ReadDir("./dumps/" + cose + "/")
	if err != nil {
		fmt.Printf("failed to read directory: dumps/%s\n", cose)
	}

	var pcaps = make(map[string]string)
	for _, f := range files {
		pcaps[f.Name()] = strconv.FormatInt(f.Size(), 10)
	}
	fmt.Printf("%v\n", pcaps);
	return pcaps
}

func init_config() {
	yamlFile, err := ioutil.ReadFile("services.yaml")
	if err != nil {
		fmt.Printf("yamlFile.Get err   #%v ", err)
		os.Exit(1)
	}

	m := make(map[string]int)
	err = yaml.Unmarshal(yamlFile, &m)
	if err != nil {
		fmt.Printf("failed to unmarshal yaml: %v\n", err)
		os.Exit(1)
	}
	port_service_map = make(map[string]string)

	for service,port := range m {
		fmt.Printf("Listening for service \x1b[33;1m%s\x1b[0m on port \x1b[34;1m%d\x1b[0m\n", service,port)
		foldername := fmt.Sprintf("dumps/%s", service)
		os.MkdirAll(foldername, os.ModePerm)
		portname := strconv.Itoa(port)
		port_service_map[portname] = service
	}

	if _, err := os.Stat("dumps"); os.IsNotExist(err) {
		fmt.Printf("directory 'dumps' does not exist!")
		os.Exit(1)
	}
}

func read_pcap(filename string)([]Packet) {
	fmt.Printf("Reading %s\n", filename)

	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		fmt.Printf("error=%s.", err)
		return nil
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets();

	var myport string = ""

	var to_ret []Packet

	i := 0;
	for packet := range packets {
		i += 1;
		var src, dest string
		var srcPort, destPort string
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			netFlow := netLayer.NetworkFlow()
			src = netFlow.Src().String()
			dest = netFlow.Dst().String()
		}
		if tcpLayer := packet.TransportLayer(); tcpLayer != nil {
			tcpFlow := tcpLayer.TransportFlow()
			srcPort = tcpFlow.Src().String()
			destPort = tcpFlow.Dst().String()
			src += ":" + srcPort
			dest += ":" + destPort

			if myport == "" {myport = destPort}

			payload := tcpLayer.LayerPayload()
			if len(payload) == 0 {continue}

			payload_hex := hex.EncodeToString(payload)
			for i := 0; i < len(payload); i++ {
				if payload[i] > 0x7f || payload[i] < 0x9 {
					payload[i] = byte(0x2e)
				}
			}
			payload_str := string(payload)
			direction := src + "  -> " + dest;
			to_ret = append(to_ret, Packet{destPort == myport, payload_str, payload_hex, direction})
		}
	}
	return to_ret
}

func serve() {
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":9001", nil)

	tmpl := template.Must(template.ParseFiles("layout/index.html"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl.Execute(w, port_service_map)
	})

	for _, service := range port_service_map {
		http.HandleFunc("/" + service + "/", func(w http.ResponseWriter, r *http.Request) {
			ss := strings.Split(r.RequestURI, "/");
			servicename := ss[1]
			if len(ss) > 2 && strings.HasSuffix(ss[2], ".pcap"){
				filename := fmt.Sprintf("dumps/%s/%s", servicename, ss[2])
				packets := read_pcap(filename)
				type pageData struct {
					Services   map[string]string
					Packets   []Packet
				}
				tmpl := template.Must(template.ParseFiles("layout/pcap.html", "layout/index.html"))
				tmpl.Execute(w, pageData{port_service_map, packets})
			} else {
				pcaps := list_pcaps(servicename)
				type pageData struct {
					Services   map[string]string
					Pcaps	   map[string]string
				}
				tmpl := template.Must(template.ParseFiles("layout/service.html", "layout/index.html"))
				tmpl.Execute(w, pageData{port_service_map, pcaps})
			}
		})
	}
	go http.ListenAndServe(":9000", nil)
	fmt.Printf("Hosting on http://localhost:9000\n")
}

func main() {
	init_config()
	serve()

	//time.Sleep(time.Second * 5)
	iface := os.Args[1]
	fmt.Printf("dumping packets on %s\n", iface)

	update_time := time.Second

	handle, err := pcap.OpenLive(iface, 65536, false, update_time)
	if err != nil {
		fmt.Printf("failed to open live: %v\n", err)
		return
	}
	link_type = handle.LinkType()

	filter := ""
	for k, _ := range port_service_map {
		if len(filter) > 0 { filter += " or " }
		filter += "port " + k
	}
	fmt.Printf("Using bpf filter \"\x1b[33m%s\x1b[0m\"\n", filter)

	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Printf("failed to set bpf filter")
	}

	stats := make(map[gopacket.Endpoint]uint64)

	packets_flow := make(map[string][]gopacket.Packet)
	packets_port := make(map[string][]gopacket.Packet)


	counter := promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tcp",
		Name:      "inbound_traffic_total_bytes",
	}, []string{
		"ip",
	})

	outbound := promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "tcp",
		Name:      "outbound_traffic_total_bytes",
	}, []string{
		"ip",
	})

	flagBytes := []byte("FAUST_")

	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSrc.Packets() {
		var src, dest string
		var srcPort, destPort string
		var srcIp gopacket.Endpoint
		//var dstIp gopacket.Endpoint
		inbound := true
		if netLayer := packet.NetworkLayer(); netLayer != nil {
			netFlow := netLayer.NetworkFlow()
			src = netFlow.Src().String()
			dest = netFlow.Dst().String()
			srcIp = netFlow.Src()
			//dstIp = netFlow.Dst()
		}
		if tcpLayer := packet.TransportLayer(); tcpLayer != nil {
			tcpFlow := tcpLayer.TransportFlow()
			srcPort = tcpFlow.Src().String()
			destPort = tcpFlow.Dst().String()
			src += ":" + srcPort
			dest += ":" + destPort
			flow_idx := src+dest;
			if _, ok := port_service_map[destPort]; ok {
				inbound = false
				flow_idx = dest+src;
			}
			//true_src := strings.ReplaceAll(strings.ReplaceAll(src, ".", "_"), ":", "_")
			packets_flow[flow_idx] = append(packets_flow[flow_idx], packet)
			packets_port[destPort] = append(packets_port[destPort], packet)
			fmt.Printf("Length: %d from %s to %s\n", len(packets_flow[flow_idx]), src, dest);
			if bytes.Contains(tcpLayer.LayerPayload(), flagBytes) {
				fmt.Printf("user %s got flag returned!\n", srcIp)
				// dump packets relative to this flow
				time := time.Now().Format("15_04_03.99")
				filename := fmt.Sprintf("%s/flag_%s.pcap", port_service_map[destPort], time)
				write_pcap(filename, packets_flow[flow_idx])
				// reset  packets of this flow, as we got flag
				// XXX: is this the right thing to do ? 
				packets_flow[flow_idx] = []gopacket.Packet{}

				// dump last 100 packets relative to this port/service (still todo)
				filename = fmt.Sprintf("%s/total_%s.pcap", port_service_map[destPort], time)
				write_pcap(filename, packets_port[destPort])
			}
		}
		stats[srcIp] += uint64(packet.Metadata().CaptureInfo.CaptureLength)
		c := counter
		if !inbound {
			c = outbound
		}
		c.WithLabelValues(srcIp.String()).Add(float64(packet.Metadata().CaptureLength))
		//fmt.Printf("Received packet from %s to %s, size: %d\n", src, dest, packet.Metadata().CaptureInfo.CaptureLength)
	}
}
