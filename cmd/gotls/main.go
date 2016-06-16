package main

import (
	//"crypto/tls"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/codegangsta/cli"
	tlschk "github.com/jamonation/gotls"
)

func main() {

	app := cli.NewApp()
	app.Name = "gotls"
	app.Version = "0.0.2"
	app.Usage = "Examine local and remote SSL keys and certificates"

	app.Flags = tlschk.AppFlags //flags live in ../../flags.go

	app.Action = func(c *cli.Context) error {
		var keyContainer tlschk.KeyContainer
		var err error

		switch {
		case tlschk.CertFile != "" && tlschk.KeyFile != "":
			keyContainer, err = tlschk.ProcessKey(keyContainer)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			keyContainer, err = tlschk.ProcessCerts(keyContainer)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}
			tlschk.PrintKeyAndCerts(keyContainer)
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

		case tlschk.Server != "":
			if tlschk.Host == "" {
				tlschk.Host = tlschk.Server
			}
			conn, err := tls.Dial("tcp", tlschk.Host+":"+strconv.Itoa(tlschk.Port), &tls.Config{InsecureSkipVerify: tlschk.InsecureSkipVerify})
			defer conn.Close()
			if err != nil {
				fmt.Println("Failed to connect: " + err.Error())
				os.Exit(1)
			}

			keyContainer, err := tlschk.CheckCerts(conn, keyContainer)
			if err != nil {
				fmt.Println(err.Error())
				os.Exit(1)
			}

			if tlschk.InsecureSkipVerify == true {
				if tlschk.Output == "json" {
					b, err := json.MarshalIndent(keyContainer.PublicKeys.PeerCertificates, "", " ")
					if err != nil {
						fmt.Println(err.Error())
						os.Exit(1)
					}
					fmt.Println(string(b))
				} else {
					for _, cert := range keyContainer.PublicKeys.PeerCertificates {
						tlschk.PrintText(*cert)
					}
				}
			}
			if tlschk.InsecureSkipVerify == false {
				if tlschk.Output == "json" {
					b, err := json.MarshalIndent(keyContainer.PublicKeys.VerifiedChains, "", " ")
					if err != nil {
						fmt.Println(err.Error())
						os.Exit(1)
					}
					fmt.Println(string(b))
				} else {
					for _, cert := range keyContainer.PublicKeys.VerifiedChains {
						tlschk.PrintText(*cert)
					}
				}
			}
		}

		return nil
	}
	
	app.Run(os.Args)

}
