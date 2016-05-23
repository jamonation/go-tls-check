package main

import (
	"fmt"
	"github.com/codegangsta/cli"
	tlschk "github.com/jamonation/go-tls-check"
	"os"
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
					tlschk.PrintText(cert)
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
		}

		return nil
	}
	app.Run(os.Args)

}
