package main

import (
	"fmt"
//        "net"
        "context"
        pb "project/proto/nbi"
	omci "project/proto/omci"
        "flag"
        "google.golang.org/grpc"
	"log"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"time"
	"sync"
	"google.golang.org/protobuf/types/known/emptypb"
	"errors"
	"io"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
	"strconv"
//	"bytes"
        "encoding/binary"
	"encoding/hex"
        "io/ioutil"
        "crypto/tls"
        "crypto/x509"
        "github.com/fsnotify/fsnotify"
	"google.golang.org/grpc/credentials"
	"os"
	opensslcgo "project/psk"
	"bufio"
//	"math"
        vpd "project/vpd"
)

var (
	vOMCIFuncServaddr = flag.String("port", "localhost:50051", "vOMCI Server Port")
	vOMCIProxyAddr    = flag.String("proxy_port", "localhost:50052", "vOMCI Proxy Port")
	tlsFlag  = flag.Bool("tls",  false, "If TLS 1.3 to be enabled")
)


var (
	//vomciFunc as Server
        vomciFunCertSrvMutex   sync.RWMutex
        vomciFunCertSrv     *tls.Certificate
        cacertPool          *x509.CertPool

	//vomciFunc as Client
	vomciFunCertClntMutex sync.RWMutex
	vomciFunCertClnt *tls.Certificate
)

const (
        vomciFunSrvFile = "../cert/vomciFunc_cert/server/vomciFuncSrv.crt"
        vomciFunSrvKey      = "../cert/vomciFunc_cert/server/vomciFuncSrv.key"
        caCertFile     = "../cert/ca/ca.crt"

	vomciFunClntFile = "../cert/vomciFunc_cert/client/vomciFunClnt.crt" 
	vomciFunClntKey = "../cert/vomciFunc_cert/client/vomciFunClnt.key"
)

func loadServerCerts() error {
        newCert, err := tls.LoadX509KeyPair(vomciFunSrvFile,vomciFunSrvKey)
        if err != nil {
                return fmt.Errorf("load Cert failed %v\n",err)
        }

        newCA, err := ioutil.ReadFile(caCertFile)
        if err != nil {
                return fmt.Errorf("load of CA failed %v\n",err)
        }

        newCAPool := x509.NewCertPool()
        newCAPool.AppendCertsFromPEM(newCA)

        vomciFunCertSrvMutex.Lock()
        vomciFunCertSrv = &newCert
        cacertPool = newCAPool
        vomciFunCertSrvMutex.Unlock()

        fmt.Printf("Client certs loaded")
        return nil
}

func loadClientCerts() error {
        newCert, err := tls.LoadX509KeyPair(vomciFunClntFile,vomciFunClntKey)
        if err != nil {
                return fmt.Errorf("load Cert failed %v\n",err)
        }

        newCA, err := ioutil.ReadFile(caCertFile)
        if err != nil {
                return fmt.Errorf("load of CA failed %v\n",err)
        }

        newCAPool := x509.NewCertPool()
        newCAPool.AppendCertsFromPEM(newCA)

        vomciFunCertClntMutex.Lock()
        vomciFunCertClnt = &newCert
        cacertPool = newCAPool
        vomciFunCertClntMutex.Unlock()

	fmt.Println("CA pool subjects:", len(cacertPool.Subjects()))
        fmt.Printf("Client certs loaded")
        return nil
}


func watchClientCerts() {
        watcher,_ := fsnotify.NewWatcher()
        defer watcher.Close()

        for _,f := range []string{vomciFunSrvFile,vomciFunSrvKey,vomciFunClntFile,vomciFunClntKey} {
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

				if err := loadServerCerts(); err != nil {
					log.Println("Failed to load server certs %v",err)
				}

                        }
                case err := <-watcher.Errors:
                        log.Println("Watcher error %v",err)
                }
        }
}


func dynamicClntTlsConfig() (*tls.Config) {
	keylogFile, _ := os.OpenFile("/tmp/sslkeys1.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
        return &tls.Config {
		KeyLogWriter: keylogFile,
                MinVersion : tls.VersionTLS13,
                RootCAs    : cacertPool,
                GetClientCertificate : func (*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			if vomciFunCertClnt != nil {
				fmt.Printf("vomci sending Cert\n")
			}
                        vomciFunCertClntMutex.RLock()
                        defer vomciFunCertClntMutex.RUnlock()
                        return vomciFunCertClnt, nil
                },
		ServerName:   "localhost",
		NextProtos:   []string{"h2"},
        }
}

func tlsConfig() (*tls.Config) {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: cacertPool,
		//Certificates: []tls.Certificate{*vomciFunCertSrv},

		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			vomciFunCertSrvMutex.RLock()
			defer vomciFunCertSrvMutex.RUnlock()
			return vomciFunCertSrv, nil
		},
		/*
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			vomciFunCertSrvMutex.RLock()
			defer vomciFunCertSrvMutex.RUnlock()
			return &tls.Config{
				//ClientAuth: tls.RequireAndVerifyClientCert,
				ClientAuth: tls.VerifyClientCertIfGiven,
				ClientCAs:  cacertPool,
				MinVersion: tls.VersionTLS13,
				Certificates: []tls.Certificate{*vomciFunCertSrv},
				NextProtos: []string{"h2"},
			},nil
		},
		*/
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            fmt.Println(">>> VerifyPeerCertificate called")
            if len(rawCerts) > 0 {
                cert, _ := x509.ParseCertificate(rawCerts[0])
                fmt.Println(">>> Got client cert CN:", cert.Subject.CommonName)
            } else {
                fmt.Println(">>> No cert received")
            }
            return nil // don’t reject — just log
        },
	}
}

/*
func DLKeyGen() []byte {
    // Replace with your DL model output
    return []byte("0123456789abcdef0123456789abcdef") // 32 bytes (example)
}
*/
func trimNewlines(s string) string {
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func DLKeyGen() []byte {
    // Replace with your DL model output
    data, err := os.ReadFile("../psk/psk_64.bin")
    if err != nil {
            log.Fatalf("Failed to read key file: %v", err)
    }
    //keyStr := string(data)
    /*
    keyStr = string([]byte(keyStr))
    keyStr = trimNewlines(keyStr)
    keyBytes, err := hex.DecodeString(keyStr)
    if err != nil {
            log.Fatalf("Failed to decode hex key: %v", err)
    }
    */
    //keyBytes := []byte(keyStr)

    //return keyBytes
    //return []byte(keyStr)
    return []byte(data)
    //return []byte("0123456789abcdef0123456789abcdef") // 32 bytes (example)
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

var count int = 0

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

func init() {
    //opensslcgo.DLKeyGen = DLKeyGen
    opensslcgo.DLKeyGen = func() []byte{
	    /*
                        psk := GetPskByIndex(psklist, count)
                        f, _ := strconv.ParseFloat(psk, 64)
                        fmt.Printf("String: %s -> Float: %f\n", psk, f)
                        b := make([]byte, 8)
                        binary.BigEndian.PutUint64(b, math.Float64bits(f))
			fmt.Printf("Print hex:%x, count:%d\n",b,count)
                        return b
			*/
                        cycler, _ := NewHexCycler("../psk/chaotic.bin", 256)
                        psk, _ := cycler.NextChunk()
                        return psk
                }
}

type server struct {
	pb.UnimplementedVomciMessageNbiServer
}

func fillHelloResp() (*pb.Msg) {
        msg := &pb.Msg {
                Header: &pb.Header {
                        MsgId : "1234",
        SenderName:    "vomci-function-1",
        RecipientName: "voltmf",
        ObjectType:    pb.Header_VOLTMF,
        ObjectName:    "vomci-fn-1",
    },
    Body: &pb.Body{
        MsgBody: &pb.Body_Response{
            Response: &pb.Response{
                RespType: &pb.Response_HelloResp{
                    HelloResp: &pb.HelloResp{
			    ServiceEndpointName : "voltmf",
			    NetworkFunctionInfo : []*pb.NFInformation {
				    &pb.NFInformation {
				    NfTypes : map[string]string{
					    "vomcFunc":"1.0",
				    },
				    Capabilities: []pb.NFInformation_NFCapability{
					    0,
				    },
			    },
			    },
			    },
                    },
                },
            },
        },
    }

    return msg
}

var omci_resp = "sn:ALCL00000001,oper:up,rx-sig:-25,tx-sig:-20"

func fillGetDataResp(omci_msg []byte) (*pb.Msg) {
        msg := &pb.Msg {
                Header: &pb.Header {
                        MsgId : "1234",
        SenderName:    "vomci-function-1",
        RecipientName: "voltmf",
        ObjectType:    pb.Header_VOLTMF,
        ObjectName:    "vomci-fn-1",
    },
    Body: &pb.Body{
        MsgBody: &pb.Body_Response{
            Response: &pb.Response{
                RespType: &pb.Response_GetResp{
                    GetResp: &pb.GetDataResp{
			    StatusResp : &pb.Status{
				    StatusCode : 0,
			    },
			    Data : vpd.Encrypt_bytes([]byte(omci_msg),vpd.LoadKeys("../psk/keys_seq_u8.bin")),
                            },
                            },
                            },
                    },
                },
            }
	    return msg
}



func (s *server) Hello(_ context.Context, req *pb.Msg) (*pb.Msg, error) {
    log.Printf("Received Header: %v",req.GetHeader())
    log.Printf("Hello Received Body: %v", req.GetBody())
    msg := fillHelloResp()
    count = count + 1
    return msg, nil
}

var reqid int = 0

func findNextReqId() (string) {

	if reqid == 65535 {
		reqid = 0
	}
	reqid++
	return strconv.Itoa(reqid)
}

func fillGetOnuGMsg() (*omci.VomciMessage) {
    msg := &omci.VomciMessage {
	    RequestPayloadId : findNextReqId(),
	    Msg : &omci.VomciMessage_OmciPacketMsg {
		    OmciPacketMsg : &omci.OmciPacket {
			    Header : &omci.OnuHeader {
				    OltName : "pOlt-1",
				    ChnlTermName : "pon-1",
				    OnuId : 1,
			    },
			    Payload : []byte {
				    0x04,0x0f,
				    0x49,
				    0x0a,
				    0x01,0x00,
				    0x00,0x00,
				    0xE0,0x00,
				    0x00,0x00,0x00,0x00,0x00,0x00,
				    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
				    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
			    },
		    },
	    },
    }

    return msg
}

func fillGetOnu2GMsg() (*omci.VomciMessage) {
    msg := &omci.VomciMessage {
            RequestPayloadId : findNextReqId(),
            Msg : &omci.VomciMessage_OmciPacketMsg {
                    OmciPacketMsg : &omci.OmciPacket {
                            Header : &omci.OnuHeader {
                                    OltName : "pOlt-1",
                                    ChnlTermName : "pon-1",
                                    OnuId : 1,
                            },
                            Payload : []byte {
                                    0x04,0x10,
                                    0x49,
                                    0x0a,
                                    0x01,0x01,
                                    0x00,0x00,
                                    0xC0,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                            },
                    },
            },
    }

    return msg
}

type vomciClientIntf struct {
	vClientItf omci.VomciMessageSbiClient
	pending map[string]chan *omci.VomciMessage
	mu sync.Mutex
}

func newvOmciClient(vClientConn *grpc.ClientConn) (*vomciClientIntf) {
	c := &vomciClientIntf {
		vClientItf : omci.NewVomciMessageSbiClient(vClientConn),
		pending :  make(map[string]chan *omci.VomciMessage),
	}
	go c.listenForVomciRx()
	return c
}

func (c *vomciClientIntf) VomciTx(msg *omci.VomciMessage) (*omci.VomciMessage,error) {
	c.mu.Lock()
	ch := make(chan *omci.VomciMessage,1)
	fmt.Printf("storing channel for request id %v\n",msg.RequestPayloadId)
	c.pending[msg.RequestPayloadId] = ch;
	c.mu.Unlock()

       ctx, cancel := context.WithCancel(context.Background())
       defer cancel()
	
	_,err := c.vClientItf.VomciTx(ctx, msg)
	if err != nil {
		return nil, err
	}

	fmt.Printf("VomciTx wait for reply\n")
	reply := <-ch 
	fmt.Printf("Received mesg %v\n",reply)
	return reply, nil
}

func (c *vomciClientIntf) listenForVomciRx() {
	fmt.Printf("Recieved via stream\n")

	for {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()		
        	stream, err := c.vClientItf.ListenForVomciRx(ctx, &emptypb.Empty{})
        	if err != nil {
                	fmt.Printf("Unable to listen to stream %v\n",err)
        	}

		if stream == nil {
			fmt.Printf("No stream\n")
			time.Sleep(time.Second)
			continue
		}
		msg, err := stream.Recv()
		fmt.Printf("Gotmsg\n")
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Printf("Stream closed by server\n")
				break
			}
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Canceled {
				fmt.Printf("Stream canceled, connection closed\n")
				break
			}
			fmt.Printf("Keep listening %v", err)
			time.Sleep(time.Second)
			continue
		}
		if msg == nil {
			fmt.Printf("Received no msg, wait\n")
			continue
		}

		c.mu.Lock()
		ch, ok := c.pending[msg.RequestPayloadId] 
		fmt.Printf("Got chaneel msg for req ID:%v %v\n",msg.RequestPayloadId,msg)
		if ok {
			fmt.Printf("Sending via channel\n")
			ch <- msg
			delete(c.pending, msg.RequestPayloadId)
		}
		c.mu.Unlock()
	}

}

type onuG struct {
        tcid uint16
        msgType uint8
        devId uint8
        meClass uint16
        meId uint16
	attr uint16
	vendorId [4]byte
	version [14]byte
	serialNum [8]byte
}

type onu2G struct {
        tcid uint16
        msgType uint8
        devId uint8
        meClass uint16
        meId uint16
        attr uint16
        equipId [20]byte
        omccVer byte
}

func parseOnuG(data []byte) (*onuG, error) {
	if data == nil {
		fmt.Printf("No data received\n")
		return nil, nil
	}

	frame := &onuG {
		tcid : binary.BigEndian.Uint16(data[0:2]),
		msgType : data[2],
		devId : data[3],
		meClass : binary.BigEndian.Uint16(data[4:6]),
		meId : binary.BigEndian.Uint16(data[6:8]),
		attr : binary.BigEndian.Uint16(data[8:10]),

	}
	copy(frame.vendorId[:],data[11:15])
	copy(frame.version[:], data[15:29])
	copy(frame.serialNum[:], data[29:35])

	return frame , nil
}

func parseOnu2G(data []byte) (*onu2G, error) {
        if data == nil {
                fmt.Printf("No data received\n")
                return nil, nil
        }
	
        frame := &onu2G {
                tcid : binary.BigEndian.Uint16(data[0:2]),
                msgType : data[2],
                devId : data[3],
                meClass : binary.BigEndian.Uint16(data[4:6]),
                meId : binary.BigEndian.Uint16(data[6:8]),
                attr : binary.BigEndian.Uint16(data[8:10]),
		omccVer : data[21],

        }
        copy(frame.equipId[:],data[11:31])

        return frame , nil
}


func obtainOnuGME() ([]byte) {
	flag.Parse()
        var conn *grpc.ClientConn
        var err error
        if(*tlsFlag) {
                conn, err = grpc.NewClient(*vOMCIProxyAddr, grpc.WithTransportCredentials(credentials.NewTLS(dynamicClntTlsConfig())))
        } else {
                conn, err = grpc.NewClient(*vOMCIProxyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
        }


	if err != nil {
		log.Fatalf("Unable to connect\n")
	}

	defer conn.Close()

	cli_conn := newvOmciClient(conn)

	msg := fillGetOnuGMsg()

	res, _ := cli_conn.VomciTx(msg)

	fmt.Printf("Response of OMCI Tx for OnuGME() %v\n",res)

	var buf omci.VomciMessage
	data, err := proto.Marshal(res)
	err = proto.Unmarshal(data, &buf)
	if err != nil {
		log.Fatalf("failed to marshal\n")
	}

	fmt.Printf("Response in byte %v\n",buf.GetOmciPacketMsg().GetPayload())

	frame, err := parseOnuG(buf.GetOmciPacketMsg().GetPayload())

	if frame != nil {
	fmt.Printf("Frame value %v\n",frame)
	fmt.Printf("VendorId : %v\n",string(frame.vendorId[:]))
	fmt.Printf("Version: %v\n",string(frame.version[:]))
	fmt.Printf("sn:%v\n",hex.EncodeToString(frame.serialNum[:]))
        }
	return data
}

func obtainOnu2GME() ([]byte) {
        flag.Parse()
        var conn *grpc.ClientConn
        var err error
        if(*tlsFlag) {
		conn, err = grpc.NewClient(*vOMCIProxyAddr, grpc.WithTransportCredentials(credentials.NewTLS(dynamicClntTlsConfig())))
	} else {
        	conn, err = grpc.NewClient(*vOMCIProxyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

        if err != nil {
                log.Fatalf("Unable to connect\n")
        }

        defer conn.Close()

        cli_conn := newvOmciClient(conn)

        msg := fillGetOnu2GMsg()

        res, _ := cli_conn.VomciTx(msg)

        fmt.Printf("Response of OMCI Tx for Onu2GME() %v\n",res)

        var buf omci.VomciMessage
        data, err := proto.Marshal(res)
        err = proto.Unmarshal(data, &buf)
        if err != nil {
                log.Fatalf("failed to marshal\n")
        }

        fmt.Printf("Response in byte %v\n",buf.GetOmciPacketMsg().GetPayload())

        frame, err := parseOnu2G(buf.GetOmciPacketMsg().GetPayload())

	if frame != nil {
        fmt.Printf("Frame value %v\n",frame)
        fmt.Printf("equip : %v\n",string(frame.equipId[:]))
        fmt.Printf("omcc: %v\n",frame.omccVer)
        }

        return data
}

func getOnuGME() ([]byte) {
	msg := obtainOnuGME()

	if msg == nil {
		fmt.Printf("No Msg received")
		return nil
	}

        var buf omci.VomciMessage
	err := proto.Unmarshal(msg, &buf)
        if err != nil {
                log.Fatalf("failed to marshal\n")
        }

        fmt.Printf("Response in byte %v\n",buf.GetOmciPacketMsg().GetPayload())

        frame, err := parseOnuG(buf.GetOmciPacketMsg().GetPayload())

	ret := fmt.Sprintf("VendorID:%s, Version:%s, SerialNumber:%x",string(frame.vendorId[:]),string(frame.version[:]),hex.EncodeToString(frame.serialNum[:]));
	msg = []byte(ret)
	return msg
}

func getOnu2GME() ([]byte) {
	msg := obtainOnu2GME()
	//msg := []byte("EquipmentId:BVMFAZ, OMCCVersion:2.5,")
        return msg
}

func (s *server) GetData(_ context.Context , req *pb.Msg) (*pb.Msg, error) {
        log.Printf("Received Header: %v",req.GetHeader())
        log.Printf("GetData Received Body: %v", req.GetBody().GetRequest().GetGetData().GetFilter())
	filter := make([][]byte,1024)
	filter = req.GetBody().GetRequest().GetGetData().GetFilter()
	omci_msg := make([]byte, 0,1024)

	for _,z := range filter {
		log.Printf("Encrypted:\n",string(z))
		z = vpd.Decrypt_bytes(z, vpd.LoadKeys("../psk/keys_seq_u8.bin"))
		log.Printf("Decrypted:%v\n",string(z))
	}

	for _,y := range filter {
		y = vpd.Decrypt_bytes(y, vpd.LoadKeys("../psk/keys_seq_u8.bin"))
		switch string(y) {
		case "onuG":
			omci_msg = append(omci_msg, getOnuGME()...)
		case "onu2G":
			omci_msg = append(omci_msg, getOnu2GME()...)
		default:
			log.Fatalf("Uknown get\n")
		}
		//log.Printf("%v: %s",x,y)
	}
        msg := fillGetDataResp(omci_msg)
	count = count + 1
        return msg, nil
}

func (s *server) ReplaceConfig(_ context.Context , req *pb.Msg) (*pb.Msg, error) {
	log.Printf("Received Header: %v",req.GetHeader())
	log.Printf("ReplaceCfg Received Body: %v", req.GetBody())
//	msg := fillReplaceConfigResp()
	return nil, nil
}


func main() {
	fmt.Println("vomciFunc started")
        flag.Parse()

	if err := loadClientCerts(); err != nil {
		log.Fatalf("unable to load client certs")
	}

        if err := loadServerCerts(); err != nil {
                log.Fatalf("unable to load client certs")
        }

	go watchClientCerts() 

	/*
	lis, err := net.Listen("tcp", *vOMCIFuncServaddr)
        if err != nil {
		log.Fatalf("Unable to start vOMCI functionserver")
	}
*/
        //psklist,_ = load_psk("../psk/psk.key")
	useCert := false
	l, err := opensslcgo.CreateOpenSSLListener(*vOMCIFuncServaddr, useCert, vomciFunSrvFile, vomciFunSrvKey)
    	if err != nil {
        	log.Fatalf("OpenSSLListener error: %v", err)
    	}
    	defer l.Close()

	var s *grpc.Server
	//if(*tlsFlag) {
	//	fmt.Printf("using Secure comm\n")
	//	s = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig())))
	//} else {
		s = grpc.NewServer()
 	//}
        pb.RegisterVomciMessageNbiServer(s, &server{})
	log.Printf("server listening on %v",l.Addr())

	if err := s.Serve(l) ; err != nil {
		log.Fatalf("fail to start server")
	}
}
