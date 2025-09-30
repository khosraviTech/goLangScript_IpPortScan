package main

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Result struct {
	IP     string
	Port   int
	Proto  string
	Status string
}

// IP list from CIDR or single host
func ipsFromCIDR(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		ip := net.ParseIP(cidr)
		if ip == nil {
			addrs, err := net.LookupHost(cidr)
			if err != nil {
				return nil, err
			}
			return addrs, nil
		}
		return []string{cidr}, nil
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	var ips []string
	for ip := ip.Mask(ipnet.Mask); /*gets the network address (puts subnet mask on ip)*/ ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil //all ips except network address & broadcast
	}
	return ips, nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(s string) ([]int, error) {
	var res []int
	parts := strings.Split(s, ",")
	set := make(map[int]struct{}) // like "set" in python. map means dictionary(key , value) & each key is unique.
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if strings.Contains(p, "-") {
			xy := strings.SplitN(p, "-", 2)
			a, err := strconv.Atoi(strings.TrimSpace(xy[0]))
			if err != nil {
				return nil, err
			}
			b, err := strconv.Atoi /*converts ascii to int */ (strings.TrimSpace(xy[1]))
			if err != nil {
				return nil, err
			}
			for i := a; i <= b; i++ {
				set[i] = struct{}{}
			}
		} else {
			n, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			set[n] = struct{}{}
		}
	}
	for k := range set {
		if k >= 1 && k <= 65535 {
			res = append(res, k)
		}
	}
	return res, nil
}

// TCP scan worker
func tcpWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Result, out chan<- Result, timeout time.Duration) {
	defer wg.Done()
	for job := range jobs {
		d := net.Dialer{}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := d.DialContext(cctx, "tcp", net.JoinHostPort(job.IP, strconv.Itoa(job.Port)))
		cancel()
		if err == nil {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "TCP", Status: "open"}
			conn.Close()
		} else {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "TCP", Status: "closed"}
		}
	}
}

// UDP scan worker with safer handling
func udpWorker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan Result, out chan<- Result, timeout time.Duration) {
	defer wg.Done()
	for job := range jobs {
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(job.IP, strconv.Itoa(job.Port)))
		if err != nil {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "UDP", Status: "resolve_error"}
			continue
		}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "UDP", Status: "dial_error"}
			continue
		}

		conn.SetDeadline(time.Now().Add(timeout))
		// Payload: small dummy data; for DNS (53) or other, could send proper query later
		_, err = conn.Write([]byte("ping"))
		if err != nil {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "UDP", Status: "write_error"}
			conn.Close()
			continue
		}

		buf := make([]byte, 1)
		_, _, err = conn.ReadFrom(buf)
		if err != nil {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "UDP", Status: "open|filtered"}
		} else {
			out <- Result{IP: job.IP, Port: job.Port, Proto: "UDP", Status: "open"}
		}
		conn.Close()
	}
}

func main() {
	target := flag.String("target", "", "Target IP or CIDR (e.g., 192.168.1.0/24)")
	portsArg := flag.String("ports", "", "Comma-separated ports (e.g., 22,80,443 or 20-25)")
	concurrency := flag.Int("concurrency", 50, "Number of workers per protocol")
	timeoutMs := flag.Int("timeout", 800, "Timeout per probe in milliseconds")
	outPath := flag.String("out", "scan_results.csv", "CSV output file")
	flag.Parse()

	if *target == "" || *portsArg == "" {
		fmt.Println("Usage: tcp_udp_scanner --target <IP/CIDR> --ports <ports> [--concurrency N] [--timeout ms] [--out file]")
		return
	}

	ips, err := ipsFromCIDR(*target)
	if err != nil {
		fmt.Println("Invalid target:", err)
		return
	}

	ports, err := parsePorts(*portsArg)
	if err != nil {
		fmt.Println("Invalid ports:", err)
		return
	}

	jobChTCP := make(chan Result, 1000)
	jobChUDP := make(chan Result, 1000)
	outCh := make(chan Result, 1000)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Start TCP workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go tcpWorker(ctx, &wg, jobChTCP, outCh, time.Duration(*timeoutMs)*time.Millisecond)
	}

	// Start UDP workers
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go udpWorker(ctx, &wg, jobChUDP, outCh, time.Duration(*timeoutMs)*time.Millisecond)
	}

	// Producer goroutine (streaming jobs)
	go func() {
		for _, ip := range ips {
			for _, port := range ports {
				jobChTCP <- Result{IP: ip, Port: port}
				jobChUDP <- Result{IP: ip, Port: port}
			}
		}
		close(jobChTCP)
		close(jobChUDP)
	}()

	// Writer goroutine
	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go func() {
		defer writerWg.Done()
		f, err := os.Create(*outPath) //open or creat the file
		if err != nil {
			fmt.Println("Write error:", err)
			os.Exit(1)
		}
		defer f.Close() //close the file
		w := csv.NewWriter(f)
		defer w.Flush() //put all writes data to csv file
		w.Write([]string{"IP", "Port", "Proto", "Status"})
		for r := range outCh {
			w.Write([]string{r.IP, strconv.Itoa(r.Port), r.Proto, r.Status})
		}
	}()

	// Wait for workers
	wg.Wait()
	close(outCh)
	writerWg.Wait()

	fmt.Println("Scan complete. Results saved to", *outPath)
}
