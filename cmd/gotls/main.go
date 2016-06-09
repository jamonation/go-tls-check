package main

import (
	//"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/codegangsta/cli"
	tlschk "github.com/jamonation/gotls"
	"os"
)

func main() {

	app := cli.NewApp()
	app.Name = "gotls"
	app.Usage = "Examine local and remote SSL keys and certificates"

	app.Flags = tlschk.AppFlags //flags live in appflags.go

	app.Action = func(c *cli.Context) error {
		var keyContainer tlschk.KeyContainer
		var err error
		/*
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
				keyModulusHash, err := tlschk.ExtractModulus(publicKey)
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
		*/

		switch {
		case tlschk.KeyFile != "":
			keyContainer, err = tlschk.ProcessKey(keyContainer)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			if tlschk.Output == "json" {
				keyContainer.PrivateKey.KeyJSON.ModulusSHA1 = keyContainer.PrivateKey.Hash
				keyContainer.PrivateKey.KeyJSON.Filename = tlschk.KeyFile
				b, err := json.MarshalIndent(keyContainer.PrivateKey.KeyJSON, "", "  ")
				if err != nil {
					fmt.Println(err.Error())
					os.Exit(1)
				}
				fmt.Println(string(b))
			} else {
				fmt.Println("Private key modulus SHA1 hash:", keyContainer.PrivateKey.Hash)
			}

		case tlschk.CertFile != "":
			keyContainer, err = tlschk.ProcessCerts(keyContainer)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			if tlschk.Output == "json" {
				b, err := json.MarshalIndent(keyContainer.PublicKeys.LocalCertificates, "", " ")
				if err != nil {
					fmt.Println(err.Error())
					os.Exit(1)
				}
				fmt.Println(string(b))
			} else {
				fmt.Println("Public key subject names:")
				for _, cert := range keyContainer.PublicKeys.LocalCertificates {
					tlschk.PrintText(*cert)
				}
			}
		}

		return nil
	}
	app.Run(os.Args)

}
