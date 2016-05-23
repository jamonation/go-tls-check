package tlschk

import (
	"github.com/codegangsta/cli"
)

var (
	CertFile string
	KeyFile  string
	Output   string
	Server   string
	Host     string
	Port     int

	AppFlags = []cli.Flag{
		cli.StringFlag{
			Name:        "cert, c",
			Usage:       "Filesystem path to public .pem file",
			Destination: &CertFile,
		},
		cli.StringFlag{
			Name:        "key, k",
			Usage:       "Filesystem path to private .key file",
			Destination: &KeyFile,
		},
		cli.StringFlag{
			Name:        "format, f",
			Value:       "text",
			Usage:       "Output format (text, json)",
			Destination: &Output,
		},
		cli.StringFlag{
			Name:        "server, s",
			Usage:       "Remote server name, e.g. golang.org",
			Destination: &Server,
		},
		cli.StringFlag{
			Name:        "host",
			Usage:       "Remote host, e.g. 216.58.220.49 or golang.org",
			Destination: &Host,
		},
		cli.IntFlag{
			Name:        "port, p",
			Value:       443,
			Usage:       "Remote HTTP port, e.g. 8443",
			Destination: &Port,
		},
	}
)
