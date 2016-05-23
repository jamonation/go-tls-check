package main

import (
	"crypto/tls"
	"fmt"
	"github.com/codegangsta/cli"
	tlschk "github.com/jamonation/go-tls-check"
	"os"
	"strconv"
)

func main() {

	app := cli.NewApp()
	app.Name = "gotls"
	app.Usage = "Examine local and remote SSL keys and certificates"

	app.Flags = tlschk.AppFlags //flags live in appflags.go

	app.Action = func(c *cli.Context) error {

		switch {

		case tlschk.CertFile != "" && tlschk.KeyFile != "":
			tlschk.CheckKeyPair()

		case tlschk.CertFile != "":
			_, _, ASN1certs := tlschk.ProcessCerts()
			if tlschk.Output == "json" {
				tlschk.PrintJSONCert(ASN1certs)
			} else {
				for _, cert := range ASN1certs {
					tlschk.PrintText(*cert)
				}
			}

		case tlschk.KeyFile != "":
			_, publicKey := tlschk.ProcessKey()
			keyModulusHash := tlschk.ExtractModulus(publicKey)
			if tlschk.Output == "json" {
				tlschk.PrintJSONKey(publicKey)
			} else {
				fmt.Println("Private key modulus SHA1 hash:", tlschk.HashMaterial(keyModulusHash))
			}

		case tlschk.Server != "":
			if tlschk.Host == "" {
				tlschk.Host = tlschk.Server
			}

			conn, err := tls.Dial("tcp", tlschk.Host+":"+strconv.Itoa(tlschk.Port), &tls.Config{InsecureSkipVerify: tlschk.InsecureSkipVerify})
			if err != nil {
				fmt.Println("Failed to connect: " + err.Error())
				os.Exit(1)
			}

			tlschk.CheckCerts(conn)
			conn.Close()
		}

		/* TODOS

		 */

		return nil
	}
	app.Run(os.Args)

}
