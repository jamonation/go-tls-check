package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"gitlab.org/jamonation/go-tls-check"
)

func main() {

	ServerName := os.Args[1]
	
	conn, err := tls.Dial("tcp", ServerName + ":443", nil)

	if err != nil {
		fmt.Println("Failed to connect: " + err.Error())
		os.Exit(1)
	}

	tlschk.CheckCerts(conn, ServerName)
	
	conn.Close()
}
