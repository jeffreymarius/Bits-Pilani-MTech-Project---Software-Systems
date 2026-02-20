package main

import (
	"fmt"
	"net"
	"io"
	"context"
	pb "project/proto/nbi"
	"flag"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"log"
	"time"
	"strings"
	"github.com/fsnotify/fsnotify"
	//"google.golang.org/grpc/credentials"
	"io/ioutil"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"os"
        opensslcgo "project/psk"
//	"encoding/hex"
        "bufio"
//	"strconv"
//	"encoding/binary"
//	"math"
        vpd "project/vpd"
//	"google.golang.org/protobuf/proto"
)

var logger *log.Logger

func initLogger() *os.File {
    logFile, err := os.OpenFile("ai_psk.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err != nil {
        log.Fatalf("Failed to open log file: %v", err)
    }

    // Create a logger that writes both to file and stdout (optional)
    logger = log.New(logFile, "",0)
    return logFile
}

func Logf(format string, v ...interface{}) {
    msg := fmt.Sprintf(format, v...) // format the string
    logger.Output(2, msg)
}

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
	tlsFlag  = flag.Bool("tls1.3",  false, "If TLS 1.3 to be enabled")
	tls12Flag = flag.Bool("tls1.2", false, "If TLS 1.2 to be enabled")
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

func DLKeyGen() []byte {
    // Replace with your DL model output
    data, err := os.ReadFile("../psk/psk.key")
    if err != nil {
	    log.Fatalf("Failed to read key file: %v", err)
    }
    keyStr := string(data)
    /*
    keyStr = string([]byte(keyStr))
    keyStr = trimNewlines(keyStr)
    if err != nil {
	    log.Fatalf("Failed to decode hex key: %v", err)
    }
    */
    //keyBytes :=[]byte(keyStr)
    return []byte(keyStr)
    //return keyBytes
    //return []byte("0123456789abcdef0123456789abcdef") // 32 bytes (example)
}
/*
func DLKeyGen() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}
*/

func init() {
    opensslcgo.DLKeyGen = DLKeyGen
}


var (
	voltmfCertMutex sync.RWMutex
	voltmfCert      *tls.Certificate
	cacertPool      *x509.CertPool
)

const (
	voltmfCertFile = "../cert/voltmf_cert/client/voltmfClnt.crt"
	voltmfKey      = "../cert/voltmf_cert/client/voltmfClnt.key"
	caCertFile     = "../cert/ca/ca.crt"
	AI_PSK_LOG     = "AI"
	STATIC_PSK_LOG = "STATIC"
)

func loadClientCerts() error {
	newCert, err := tls.LoadX509KeyPair(voltmfCertFile, voltmfKey)
	if err != nil {
		return fmt.Errorf("load Cert failed %v\n",err)
	}
	
	newCA, err := ioutil.ReadFile(caCertFile)
	if err != nil {
		return fmt.Errorf("load of CA failed %v\n",err)
	}

	newCAPool := x509.NewCertPool()
	newCAPool.AppendCertsFromPEM(newCA)

	voltmfCertMutex.Lock()
	voltmfCert = &newCert
	cacertPool = newCAPool
	voltmfCertMutex.Unlock()

	fmt.Printf("Client certs loaded")
	return nil
}

func watchClientCerts() {
	watcher,_ := fsnotify.NewWatcher()
	defer watcher.Close()

	for _,f := range []string{voltmfCertFile,voltmfKey} {
		watcher.Add(f)
	}

	for {
		select {
		case event := <-watcher.Events:
			if event.Op&(fsnotify.Write | fsnotify.Create) != 0{
				log.Println("Client cert changed,%v",event.Name)
				if err := loadClientCerts(); err != nil {
					log.Println("Failed to load certs: %v", err)
				}
				
			}
		case err := <-watcher.Errors:
			log.Println("Watcher error %v",err)
		}
	}
}

func opensslDialer(ctx context.Context, addr string) (net.Conn, error) {
    // DL key is provided inside DLKeyGen
    // useCert=false for PSK-only, set true to use client cert
    conn, err := opensslcgo.OpenSSLDial(addr, false, voltmfCertFile, voltmfKey)
    return conn, err
}

func dynamicTlsConfig() (*tls.Config) {
        keylogFile, _ := os.OpenFile("/tmp/sslkeys.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if(*tls12Flag) {
		fmt.Printf("Tls1.2 initaited")
                return &tls.Config {
                        MinVersion : tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
                        RootCAs    : cacertPool,
                        //Certificates: []tls.Certificate{*voltmfCert},
                        KeyLogWriter: keylogFile,
                        GetClientCertificate : func (*tls.CertificateRequestInfo) (*tls.Certificate, error) {
                                voltmfCertMutex.RLock()
                                defer voltmfCertMutex.RUnlock()
                                return voltmfCert, nil
                        },
                        ServerName:   "localhost",
                }

	} else {
		fmt.Printf("Tls1.3 initiated")
		return &tls.Config {
			MinVersion : tls.VersionTLS13,
			RootCAs    : cacertPool,
			//Certificates: []tls.Certificate{*voltmfCert},
			KeyLogWriter: keylogFile,
			GetClientCertificate : func (*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				voltmfCertMutex.RLock()
				defer voltmfCertMutex.RUnlock()
				return voltmfCert, nil
			},
			ServerName:   "localhost",
		}
	}
}

func fillHelloReq() (*pb.Msg) {
	msg := &pb.Msg {
		Header: &pb.Header {
			MsgId : "1234",
        SenderName:    "client-1",
        RecipientName: "vomci-function-1",
        ObjectType:    pb.Header_VOMCI_FUNCTION,
        ObjectName:    "vomci-fn-1",
    },
    Body: &pb.Body{
        MsgBody: &pb.Body_Request{
            Request: &pb.Request{
                ReqType: &pb.Request_Hello{
                    Hello: &pb.Hello{
                        ServiceEndpointName: "my-endpoint",
                    },
                },
            },
        },
    },
}

    return msg
}

func generateHelloRpc() {
	flag.Parse()

	var conn *grpc.ClientConn
	var err error
	if(*tlsFlag || *tls12Flag) {
        conn, err = grpc.Dial(
            *addr,
            grpc.WithContextDialer(opensslDialer),
            grpc.WithTransportCredentials(insecure.NewCredentials()), // transport is already secured by underlying conn
        )
	} else {
		conn, err = grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if err != nil {
		log.Fatalf("Unable to connect: %v", err)
	}

	defer conn.Close()

        cli_rpc := pb.NewVomciMessageNbiClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	msg := fillHelloReq()

	res,_ := cli_rpc.Hello(ctx, msg)

	fmt.Printf("Hello Message reply : %v\n",res)
}

func fillGetOntOperReq() (*pb.Msg) {
        msg := &pb.Msg {
                Header: &pb.Header {
                        MsgId : "1234",
        SenderName:    "voltmf",
        RecipientName: "vomci-function-1",
        ObjectType:    pb.Header_VOMCI_FUNCTION,
        ObjectName:    "vomci-fn-1",
    },
    Body: &pb.Body{
        MsgBody: &pb.Body_Request{
            Request: &pb.Request{
                ReqType: &pb.Request_GetData{
                        GetData: &pb.GetData {
				Filter : [][]byte {
					vpd.Encrypt_bytes([]byte("onuG"), vpd.LoadKeys("../psk/keys_seq_u8.bin")),
					vpd.Encrypt_bytes([]byte("onu2G"),vpd.LoadKeys("../psk/keys_seq_u8.bin")),
				},
			},
                    },
                },
            },
        },
    }
    return msg
}

func fillSetOntTod() (*pb.Msg) {
        msg := &pb.Msg {
                Header: &pb.Header {
                        MsgId : "1234",
        SenderName:    "voltmf",
        RecipientName: "vomci-function-1",
        ObjectType:    pb.Header_VOMCI_FUNCTION,
        ObjectName:    "vomci-fn-1",
    },
    Body: &pb.Body{
        MsgBody: &pb.Body_Request{
            Request: &pb.Request{
                ReqType: &pb.Request_ReplaceConfig{
                        ReplaceConfig: &pb.ReplaceConfig {
                                ConfigInst : []byte("ontTodConfig"),
                                },
                        },
                    },
                },
            },
        }
    return msg	
}


func generateGetOntOperReq() {
        defer func() {
            if r := recover(); r != nil {
                log.Printf("Recovered loop panic: %v\n", r)
            }
        }()

        flag.Parse()

	var conn *grpc.ClientConn
	var err error
        if(*tlsFlag || *tls12Flag) {
		fmt.Printf("Using Secure comm\n")
        conn, err = grpc.Dial(
            *addr,
            grpc.WithContextDialer(opensslDialer),
            grpc.WithTransportCredentials(insecure.NewCredentials()), // transport is already secured by underlying conn
        )
        } else {
                conn, err = grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
        }


        if err != nil {
                log.Fatalf("Unable to connect: %v", err)
        }

     //   defer conn.Close()

        cli_rpc := pb.NewVomciMessageNbiClient(conn)

        ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
        defer cancel()

        msg := fillGetOntOperReq()

        res,_ := cli_rpc.GetData(ctx, msg)

	data := res.GetBody().GetResponse().GetGetResp().GetData()

	z := vpd.Decrypt_bytes(data,vpd.LoadKeys("../psk/keys_seq_u8.bin"))
	fmt.Printf("Decrypted bytes:%v\n",string(z))


//        fmt.Printf("Get Ont Oper Message reply : %v\n",res)	
}

func generateGetOntOperReqTLS() (tlsMs, totalMs int64, err error){
	start := time.Now()
        defer func() {
            if r := recover(); r != nil {
                log.Printf("Recovered loop panic: %v\n", r)
            }
        }()

        flag.Parse()

        tlsStart := time.Now()	
        var conn *grpc.ClientConn
        if(*tlsFlag || *tls12Flag) {
                fmt.Printf("Using Secure comm\n")
        conn, err = grpc.Dial(
            *addr,
            grpc.WithContextDialer(opensslDialer),
            grpc.WithTransportCredentials(insecure.NewCredentials()), // transport is already secured by underlying conn
        )
        } else {
                conn, err = grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
        }

        tlsMs = time.Since(tlsStart).Milliseconds()	
        if err != nil {
                log.Fatalf("Unable to connect: %v", err)
        }

     //   defer conn.Close()

        cli_rpc := pb.NewVomciMessageNbiClient(conn)

        ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
        defer cancel()

        msg := fillGetOntOperReq()

        res,_ := cli_rpc.GetData(ctx, msg)

        totalMs = time.Since(start).Milliseconds()
	Logf("PSK_TYPE=%s TransactionLatency_ms=%d\n",AI_PSK_LOG,totalMs)
        data := res.GetBody().GetResponse().GetGetResp().GetData()

        z := vpd.Decrypt_bytes(data,vpd.LoadKeys("../psk/keys_seq_u8.bin"))
        fmt.Printf("Decrypted bytes:%v\n",string(z))


        fmt.Printf("Get Ont Oper Message reply : %v\n",res)
	return
}

func generateHelloTLS() (tlsMs, totalMs int64, err error){
        start := time.Now()
        defer func() {
            if r := recover(); r != nil {
                log.Printf("Recovered loop panic: %v\n", r)
            }
        }()

        flag.Parse()

        tlsStart := time.Now()
        var conn *grpc.ClientConn
        if(*tlsFlag || *tls12Flag) {
                fmt.Printf("Using Secure comm\n")
        conn, err = grpc.Dial(
            *addr,
            grpc.WithContextDialer(opensslDialer),
            grpc.WithTransportCredentials(insecure.NewCredentials()), // transport is already secured by underlying conn
        )
        } else {
                conn, err = grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
        }

        tlsMs = time.Since(tlsStart).Milliseconds()
        if err != nil {
                log.Fatalf("Unable to connect: %v", err)
        }

     //   defer conn.Close()

        cli_rpc := pb.NewVomciMessageNbiClient(conn)

        ctx, cancel := context.WithTimeout(context.Background(), time.Second * 10)
        defer cancel()

        msg := fillHelloReq()

        res,_ := cli_rpc.Hello(ctx, msg)

     

        totalMs = time.Since(start).Milliseconds()
        Logf("PSK_TYPE=%s TransactionLatency_ms=%d\n",AI_PSK_LOG,totalMs)
        fmt.Printf("Hello Message reply : %v\n",res)
        return
}


func generateSetTod() {
        flag.Parse()
        conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))

        if err != nil {
                log.Fatalf("Unable to connect: %v", err)
        }

        defer conn.Close()

        cli_rpc := pb.NewVomciMessageNbiClient(conn)

        ctx, cancel := context.WithTimeout(context.Background(), time.Second)
        defer cancel()

        msg := fillSetOntTod()

        res,_ := cli_rpc.Hello(ctx, msg)

        fmt.Printf("Set ToD Message reply : %v\n",res)	
}

func recvFromCli() {
	conn, err := net.Listen("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}

	defer conn.Close()

	for {
		client, err := conn.Accept()

		if err != nil {
			panic(err)
		}

		go func(clnt io.Reader) {
			buffer := make([]byte, 1024)

			num,err := clnt.Read(buffer)
			if err != nil {
				panic(err)
			}

			input := buffer[:num]
			switch strings.TrimSpace((string(input))) {
			case "send_hello":
				generateHelloRpc()
			case "getOntOper":
				generateGetOntOperReq()
			case "setTOD":
				generateSetTod()
			default :
				fmt.Printf("Cmd %s not available to process",string(buffer))
			}
		}(client)
	}
}

/*
var psklist []string

func load_psk(filename string)([]string, error) {
        file, err := os.Open(filename)
        if err != nil {
                return nil, err
        }

	defer file.Close()
        var lines []string
        scanner := bufio.NewScanner(file)
        for scanner.Scan() {
                line := scanner.Text()
                lines = append(lines, line)
        }

        if err := scanner.Err(); err != nil {
                return nil, err
        }

        return lines, err
}

func GetPskByIndex(pskList []string, index int)(string) {
	return psklist[index%len(psklist)]
}
*/

type HexCycler struct {
    f      *os.File
    reader *bufio.Reader
    size   int
}

func NewHexCycler(path string, chunkSize int) (*HexCycler, error) {
    f, err := os.Open(path)
    if err != nil {
        return nil, err
    }
    return &HexCycler{f: f, reader: bufio.NewReader(f), size: chunkSize}, nil
}

func (h *HexCycler) NextChunk() ([]byte, error) {
    buf := make([]byte, h.size)
    n, err := io.ReadFull(h.reader, buf)
    if err != nil {
        if err == io.EOF || err == io.ErrUnexpectedEOF {
            _, _ = h.f.Seek(0, io.SeekStart)
            h.reader.Reset(h.f)
            return h.NextChunk()
        }
        return nil, err
    }
    return buf[:n],err
    //return hex.DecodeString(string(buf[:n]))
}

var count int = 0
func worker(id int, wg *sync.WaitGroup, out chan string) {
        defer wg.Done()
        // a simple loop: do as many connects as possible for a few seconds
        // For external control, the outer script runs for N seconds; here we'll do single measurement per call
	for i:=0; i < 1000; i++ {
		opensslcgo.DLKeyGen = func() []byte{
			/*
			psk := GetPskByIndex(psklist, count)
                        f, _ := strconv.ParseFloat(psk, 64)
			fmt.Printf("String: %s -> Float: %.18f\n", psk, f)
			b := make([]byte, 8)
			binary.BigEndian.PutUint64(b, math.Float64bits(f))
			fmt.Printf("Print hex:%x  count:%d\n",b,count)
			return b
			*/
			cycler, _ := NewHexCycler("../psk/chaotic.bin", 256)
			psk, _ := cycler.NextChunk()
			return psk

		}
        	tlsMs, totalMs, err := generateGetOntOperReqTLS()
		count = count + 1
		generateHelloTLS()
		count = count + 1
        	timestamp := time.Now().Format(time.RFC3339Nano)
        	if err != nil {
                	logger.Println("PSK_TYPE=%s TransactionLatency_ms=%f\n",AI_PSK_LOG,totalMs)
                	return
        	}
        	out <- fmt.Sprintf("%s,%d,%d,OK,%d", timestamp, tlsMs, totalMs,count)
	}
}

func main() {
    defer func() {
        if r := recover(); r != nil {
            log.Printf("MAIN recovered from panic: %v\n", r)
        }
    }()
	f := initLogger()
	defer f.Close()
	fmt.Println("starting voltmf")

	if err := loadClientCerts(); err != nil {
		log.Fatal("Initial TLS load failed:", err)
	}

//	flag.Parse()
//	fmt.Printf("add %v tls %v\n",*addr,*tlsFlag)
	go watchClientCerts()

	go recvFromCli()

        out := make(chan string, 100000)
        var wg sync.WaitGroup
	//psklist,_ = load_psk("../psk/psk.key")
        // opensslcgo.DLKeyGen = func() []byte {
        //        data, err := os.ReadFile("../psk/psk_64.bin")
        //            if err != nil {
        //                    log.Fatalf("Failed to read key file: %v", err)
        //            }
                    //keyStr := string(data)
		    /*
                    keyStr = string([]byte(keyStr))
                    keyStr = trimNewlines(keyStr)
            keyBytes, err := hex.DecodeString(keyStr)
            if err != nil {
                    log.Fatalf("Failed to decode hex key: %v", err)
            }

         return keyBytes
	*/
	//return []byte(keyStr)
//	return []byte(data)
	//return []byte("0123456789abcdef0123456789abcdef")
//         }
	

        // CSV header
        fmt.Println("time,tls_ms,total_ms,status,info")

        for i := 0; i < *concurrency; i++ {
                wg.Add(1)
                go func(id int) {
                        worker(id, &wg, out)
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

	select {}
}
