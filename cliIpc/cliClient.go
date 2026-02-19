package cliClient

import (
	"net"
)

func RecvCmd(cmd string) {
	conn,err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}

	conn.Write([]byte(cmd))
}
