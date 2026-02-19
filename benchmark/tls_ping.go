// tls_ping.go
package main

import (
//	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
	opensslcgo "project/psk"
	"encoding/hex"
	"log"
)

var (
	host      = flag.String("host", "127.0.0.1", "server host")
	port      = flag.Int("port", 50051, "server port")
	concurrency = flag.Int("concurrency", 1, "number of concurrent goroutines")
	payload   = flag.Int("payload", 0, "bytes to send after handshake (0 = handshake-only)")
	duration  = flag.Int("duration", 30, "duration seconds (ignored by this simple runner; use outer script)")
)


func trimNewlines(s string) string {
        for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
                s = s[:len(s)-1]
        }
        return s
}


const (
        voltmfCertFile = "../cert/voltmf_cert/client/voltmfClnt.crt"
        voltmfKey      = "../cert/voltmf_cert/client/voltmfClnt.key"
)


func measureOnce(addr string, payloadSize int) (tcpMs, tlsMs, totalMs int64, err error) {
	start := time.Now()

	// TCP phase
	tcpStart := time.Now()
	tcpConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, 0, 0, err
	}
	tcpMs = time.Since(tcpStart).Milliseconds()
	tcpConn.Close()

	tlsStart := time.Now()
	conn, err := opensslcgo.OpenSSLDial(addr, false, voltmfCertFile, voltmfKey)
	if err != nil {
		return tcpMs, 0, 0, err
	}
	tlsMs = time.Since(tlsStart).Milliseconds()

	// Optional payload
	if payloadSize > 0 {
		data := make([]byte, payloadSize)
		_, _ = conn.Write(data)
	}
	conn.Close()

	totalMs = time.Since(start).Milliseconds()
	return
}

func worker(id int, addr string, payload int, wg *sync.WaitGroup, out chan string) {
	defer wg.Done()
	// a simple loop: do as many connects as possible for a few seconds
	// For external control, the outer script runs for N seconds; here we'll do single measurement per call
	tcpMs, tlsMs, totalMs, err := measureOnce(addr, payload)
	timestamp := time.Now().Format(time.RFC3339Nano)
	if err != nil {
		out <- fmt.Sprintf("%s,%d,%d,%d,ERR,%q", timestamp, tcpMs, tlsMs, totalMs, err.Error())
		return
	}
	out <- fmt.Sprintf("%s,%d,%d,%d,OK,", timestamp, tcpMs, tlsMs, totalMs)
}

func main() {
	flag.Parse()
	addr := fmt.Sprintf("%s:%d", *host, *port)
	out := make(chan string, 100000)
	var wg sync.WaitGroup

	 opensslcgo.DLKeyGen = func() []byte {
    		data, err := os.ReadFile("../psk/psk.key")
		    if err != nil {
		            log.Fatalf("Failed to read key file: %v", err)
		    }
		    keyStr := string(data)
		    keyStr = string([]byte(keyStr))
		    keyStr = trimNewlines(keyStr)
	    keyBytes, err := hex.DecodeString(keyStr)
	    if err != nil {
        	    log.Fatalf("Failed to decode hex key: %v", err)
	    }

   	 return keyBytes
		 
	 }
	// CSV header
	fmt.Println("time,tcp_ms,tls_ms,total_ms,status,info")

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func(id int) {
			worker(id, addr, *payload, &wg, out)
		}(i)
	}

	// read outputs until workers finished
	go func() {
		wg.Wait()
		close(out)
	}()

	for line := range out {
		fmt.Println(line)
	}
}

