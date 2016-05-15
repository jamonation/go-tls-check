package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"gitlab.org/jamonation/go-tls-check"
)

var ServerName = flag.String("server","","The DNS name of the server name to check")
var Port = flag.String("", "", "")
var HostName = flag.String("host","","(optional) The hostname or IP of the server to connect to. Use in combination with -k/-noverify to test remote IPs")
var InsecureSkipVerify = flag.Bool("noverify", false, "Turn off validation. Use with -host and IP addresses for best results")

func init() {
	flag.StringVar(ServerName, "s", "", "The name of the server name to check")
	flag.StringVar(Port, "p", "443", "(default 443) The port on the remote server to check")
	flag.BoolVar(InsecureSkipVerify, "k", false, "Turn off validation")	

}


func main() {
	
	flag.Parse()

	if (*ServerName == "") {
		fmt.Println("You must provide a -server argument")
		os.Exit(1)
	}

	if (*HostName == "") {
		HostName = ServerName
	}	
	
	conn, err := tls.Dial("tcp", *HostName + ":" + *Port, &tls.Config{InsecureSkipVerify: *InsecureSkipVerify})

	if err != nil {
		fmt.Println("Failed to connect: " + err.Error())
		os.Exit(1)
	}

	tlschk.CheckCerts(conn, *HostName, *ServerName, *InsecureSkipVerify)
	
	conn.Close()
}
