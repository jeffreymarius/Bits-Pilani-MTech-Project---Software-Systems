package main

import (
        "fmt"
        "net"
        "context"
        omci "project/proto/omci"
        "flag"
        "google.golang.org/grpc"
        "log"
        //"google.golang.org/grpc/credentials/insecure"
        //"google.golang.org/protobuf/proto"
        //"time"
	"google.golang.org/protobuf/types/known/emptypb"
	"encoding/binary"
	"google.golang.org/protobuf/proto"
        "crypto/tls"
        "crypto/x509"
        "github.com/fsnotify/fsnotify"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"sync"
)

const (
        vomciProxySrvFile = "../cert/vomciProxy_cert/server/vomciProxySrv.crt"
        vomciProxySrvKey      = "../cert/vomciProxy_cert/server/vomciProxySrv.key"
        caCertFile     = "../cert/ca/ca.crt"
)

var (
        //vomciProxy as Server
        vomciProxyCertSrvMutex   sync.RWMutex
        vomciProxyCertSrv     *tls.Certificate
        cacertPool          *x509.CertPool
)

func loadServerCerts() error {
        newCert, err := tls.LoadX509KeyPair(vomciProxySrvFile,vomciProxySrvKey)
        if err != nil {
                return fmt.Errorf("load Cert failed %v\n",err)
        }

        newCA, err := ioutil.ReadFile(caCertFile)
        if err != nil {
                return fmt.Errorf("load of CA failed %v\n",err)
        }

        newCAPool := x509.NewCertPool()
        newCAPool.AppendCertsFromPEM(newCA)

        vomciProxyCertSrvMutex.Lock()
        vomciProxyCertSrv = &newCert
        cacertPool = newCAPool
        vomciProxyCertSrvMutex.Unlock()

        fmt.Printf("Client certs loaded")
        return nil
}

func watchCerts() {
        watcher,_ := fsnotify.NewWatcher()
        defer watcher.Close()

        for _,f := range []string{vomciProxySrvFile,vomciProxySrvKey} {
                watcher.Add(f)
        }

        for {
                select {
                case event := <-watcher.Events:
                        if event.Op&(fsnotify.Write | fsnotify.Create) != 0{
                                log.Println("Server cert changed,%v",event.Name)

                                if err := loadServerCerts(); err != nil {
                                        log.Println("Failed to load server certs %v",err)
                                }

                        }
                case err := <-watcher.Errors:
                        log.Println("Watcher error %v",err)
                }
        }
}

func tlsConfig() (*tls.Config) {
        return &tls.Config{
                MinVersion: tls.VersionTLS13,
                ClientAuth: tls.RequireAndVerifyClientCert,
                ClientCAs: cacertPool,

                GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
                        vomciProxyCertSrvMutex.RLock()
                        defer vomciProxyCertSrvMutex.RUnlock()
                        return vomciProxyCertSrv, nil
                },
                VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            fmt.Printf(">>> VerifyPeerCertificate called")
            if len(rawCerts) > 0 {
                cert, _ := x509.ParseCertificate(rawCerts[0])
                fmt.Printf(">>> Got client cert CN:", cert.Subject.CommonName)
            } else {
                fmt.Printf(">>> No cert received")
            }
            return nil // don’t reject — just log
        },
	NextProtos:         []string{"h2"},
    VerifyConnection: func(cs tls.ConnectionState) error {
        fmt.Println(">>> VerifyConnection invoked")
        fmt.Printf(" PeerCertificates=%d VerifiedChains=%d\n", len(cs.PeerCertificates), len(cs.VerifiedChains))
        for i, pc := range cs.PeerCertificates {
            fmt.Printf("  PeerCert[%d] Subject=%s\n", i, pc.Subject)
        }
        for i, chain := range cs.VerifiedChains {
            fmt.Printf("  VerifiedChain[%d]:\n", i)
            for j, c := range chain {
                fmt.Printf("    [%d] %s\n", j, c.Subject)
            }
        }
        // Return nil to allow connection; change to return an error only for experiments
        return nil
    },	
        }
}



var (
        vOMCIFuncServaddr = flag.String("port", "localhost:50051", "vOMCI Server Port")
        vOMCIProxyAddr    = flag.String("proxy_port", "localhost:50052", "vOMCI Proxy Port")
	tlsFlag  = flag.Bool("tls",  false, "If TLS 1.3 to be enabled")
)
type server struct {
	omci.UnimplementedVomciMessageSbiServer
	msgChn chan *omci.VomciMessage
}

func newOmciProxyServer() (*server) {
	return &server {
		msgChn : make(chan *omci.VomciMessage, 10),
	}
}


type omciHdr struct {
	tcid uint16
	msgType uint8
	devId uint8
	meClass uint16
	meId uint16
}

func parseOmci(data []byte) (uint16, error) {
        frame := &omciHdr {
                tcid : binary.BigEndian.Uint16(data[0:2]),
                msgType : data[2],
                devId : data[3],
                meClass : binary.BigEndian.Uint16(data[4:6]),
                meId : binary.BigEndian.Uint16(data[6:8]),

        }

	ret := frame.meClass
        return ret, nil
}

const (
	OnuG uint16= iota + 256
	Onu2G
)

func (s *server) VomciTx(_ context.Context, in *omci.VomciMessage)(*emptypb.Empty, error) {
	fmt.Printf("Received Msg %v\n", in)
        var buf omci.VomciMessage
        data, _ := proto.Marshal(in)
        proto.Unmarshal(data, &buf)
        fmt.Printf("Response in byte %v\n",buf.GetOmciPacketMsg().GetPayload())

        meId, _ := parseOmci(buf.GetOmciPacketMsg().GetPayload())
	fmt.Printf("meId: %v\n",meId)


	var response *omci.VomciMessage
	if meId == OnuG {
		response = &omci.VomciMessage {
		RequestPayloadId : in.RequestPayloadId,
		 Msg : &omci.VomciMessage_OmciPacketMsg {
                    OmciPacketMsg : &omci.OmciPacket {
                            Header : &omci.OnuHeader {
                                    OltName : "pOlt-1",
                                    ChnlTermName : "pon-1",
                                    OnuId : 1,
                            },
                            Payload : []byte {
                                    0x04,0x0f,
                                    0x29,
                                    0x0a,
                                    0x01,0x00,
                                    0x00,0x00,
				    0x00,
                                    0xC0,0x00,
				    0x41,0x4C,0x43,0x4C,
				    0x32,0x34,0x2E,0x32,0x2E,0x30,0x2E,0x30,0x2E,0x35,0x33,
				    0x00,0x00,0x00,
				    0xFA,0xEA,0x21,0x11,10,
                            },
			 
		 },

	},
    }
    } else if meId == Onu2G {
	    response = &omci.VomciMessage {
                RequestPayloadId : in.RequestPayloadId,
                 Msg : &omci.VomciMessage_OmciPacketMsg {
                    OmciPacketMsg : &omci.OmciPacket {
                            Header : &omci.OnuHeader {
                                    OltName : "pOlt-1",
                                    ChnlTermName : "pon-1",
                                    OnuId : 1,
                            },
                            Payload : []byte {
                                    0x04,0x10,
                                    0x29,
                                    0x0a,
                                    0x01,0x01,
                                    0x00,0x00,
                                    0x00,
                                    0xC0,0x00,
				    0x42,0x56,0x4D,0x47,0x5A,0x58,0x41,0x41,0x52,0x43,0x41,0x41,0x53,0x46,0x51,0x43,0x41,0x41,0x41,0x44,
                                    0xA0,
                            },

                 },

        },
    }
	    
    }

    go func() {s.msgChn <- response}()

    return &emptypb.Empty{}, nil
}

func (s *server) ListenForVomciRx(data *emptypb.Empty, stream grpc.ServerStreamingServer[omci.VomciMessage]) error {
	fmt.Printf("Streaming Msg\n")
	for {
		select {
		case <- stream.Context().Done():
			fmt.Println("Module disconnected\n")
			return nil
		case msg := <-s.msgChn:
			if msg == nil {
				continue
			}
			fmt.Printf("Received msg in channel %v\n",msg)
				if err := stream.Send(msg); err != nil {
					fmt.Printf("error sending message\n");
					return err
				}
			fmt.Printf("sent reply\n")
		}
	}
	return nil
}

func main() {
	fmt.Println("vOmciProxy started")
	flag.Parse()

        if err := loadServerCerts(); err != nil {
                log.Fatalf("unable to load client certs")
        }

        go watchCerts()

	lis, err := net.Listen("tcp", *vOMCIProxyAddr)

	if err != nil {
		log.Fatalf("failed to bind server\n")
	}

        var s *grpc.Server
        if(*tlsFlag) {
                fmt.Printf("using Secure comm\n")
                s = grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig())))
        } else {
                s = grpc.NewServer()
        }
	
	server := newOmciProxyServer() 
        omci.RegisterVomciMessageSbiServer(s, server)

	log.Printf("Server listening on %v\n",lis.Addr())

	if err := s.Serve(lis) ; err != nil {
		log.Fatalf("Failed to start server\n")
	}

}
