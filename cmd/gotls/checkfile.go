package main

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/codegangsta/cli"
	tlschk "github.com/jamonation/go-tls-check"
	"math/big"
	"net"
	"os"
	"time"
)

func readFile(f string) []byte {
	file, err := os.Open(f)
	if err != nil {
		fmt.Println("ERROR:", err.Error())
		os.Exit(1)
	}

	info, err := os.Stat(f)
	if err != nil {
		fmt.Println("ERROR:", err.Error())
		os.Exit(1)
	}

	fileSize := info.Size()
	rawFile := make([]byte, fileSize-1) // because number of bytes starts at 1

	file.Read(rawFile)
	return rawFile
}

// Decode PEM encoded block, return block, and any extra bytes
func decodeMaterial(p []byte) (*pem.Block, []byte) {
	decodedMaterial, rest := pem.Decode(p)
	return decodedMaterial, rest
}

func decodeKey(rawKey []byte) *rsa.PrivateKey {

	decodedKey, rest := decodeMaterial(rawKey)
	if len(rest) > 0 {
		fmt.Printf("Found invalid or non-key material in %s:\n", tlschk.KeyFile)
		fmt.Println(string(rest))
	}

	decodedKeyASN1, err := x509.ParsePKCS1PrivateKey(decodedKey.Bytes)
	if err != nil {
		fmt.Println("Unable to parse private key. Error was:")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return decodedKeyASN1
}

// decode
func decodeCert(certBlock *pem.Block) *x509.Certificate {
	decodedCertASN1, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("Unable to parse public certificate. Error was:")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return decodedCertASN1
}

func hashMaterial(material string) string {
	h := sha1.New()
	h.Write([]byte(material))
	shaSum := h.Sum(nil)
	hash := hex.EncodeToString(shaSum)
	return hash
}

// WHERE IS THE ERROR HANDLING!? Or, should this never be reached if there's no modulus?
func extractModulus(publicKey interface{}) string {
	var modulus string

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		modulus = key.N.String()
	case *big.Int:
		modulus = key.String()
	}
	return modulus
}

func processCerts() ([]byte, []interface{}, []x509.Certificate) {
	var cert *pem.Block
	var certASN1 *x509.Certificate

	//var splitRawCerts [][]byte
	var ASN1certs []x509.Certificate
	var publicKeys []interface{}

	rawCerts := readFile(tlschk.CertFile)
	rest := rawCerts

	for len(rest) > 0 {
		cert, rest = decodeMaterial(rest)
		certASN1 = decodeCert(cert)
		ASN1certs = append(ASN1certs, *certASN1)
		publicKey := extractModulus(certASN1.PublicKey)
		publicKeys = append(publicKeys, publicKey)
	}

	return rawCerts, publicKeys, ASN1certs
}

func processKey() ([]byte, *big.Int) {
	var privateKey *rsa.PrivateKey
	var publicKey *big.Int

	rawKey := readFile(tlschk.KeyFile)
	privateKey = decodeKey(rawKey)
	publicKey = privateKey.PublicKey.N
	return rawKey, publicKey
}

func checkKeyPair() {
	_, keyPublicKey := processKey()
	_, _, ASN1Certs := processCerts()

	keyModulus := extractModulus(keyPublicKey)
	keyModulusHash := hashMaterial(keyModulus)

	for i, _ := range ASN1Certs {
		certModulus := extractModulus(ASN1Certs[i].PublicKey)
		certModulusHash := hashMaterial(certModulus)
		if certModulus != keyModulus {
			fmt.Println("\nPublic and private keys DO NOT MATCH.")
		} else {
			fmt.Println("\nPublic and private keys MATCH")
		}
		fmt.Println("Private key modulus SHA1 hash:", keyModulusHash)
		fmt.Println("Public cert modulus SHA1 hash:", certModulusHash)
	}
	return
}

func printJSONKey(publicKey *big.Int) {

	key := KeyJSON{
		ModulusSHA1: hashMaterial(extractModulus(publicKey)),
	}
	jsonData, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling json")
	}
	fmt.Println(string(jsonData))

	return
}

func printJSONCert(rawCerts []x509.Certificate) {

	var certs []CertJSON

	for _, c := range rawCerts {
		certs = append(certs, CertJSON{
			CommonName:      c.Subject.CommonName,
			SerialNumber:    c.SerialNumber,
			Issuer:          c.Issuer.CommonName,
			IsCA:            c.IsCA,
			NotBefore:       c.NotBefore,
			NotAfter:        c.NotAfter,
			DNSNames:        c.DNSNames,
			EmailAddresses:  c.EmailAddresses,
			IPAddresses:     c.IPAddresses,
			SHA1Fingerprint: hashMaterial(string(c.Raw)),
			ModulusSHA1:     hashMaterial(extractModulus(c.PublicKey)),
		})
	}
	jsonData, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling json")
	}
	fmt.Println(string(jsonData))

	return
}

type KeyJSON struct {
	ModulusSHA1 string
}

type CertJSON struct {
	CommonName      string
	NotBefore       time.Time
	NotAfter        time.Time
	SerialNumber    *big.Int
	SHA1Fingerprint string
	ModulusSHA1     string
	Issuer          string
	IsCA            bool
	DNSNames        []string
	EmailAddresses  []string
	IPAddresses     []net.IP
}

func main() {

	app := cli.NewApp()
	app.Name = "gotls"
	app.Usage = "Examine local and remote SSL keys and certificates"

	app.Flags = tlschk.AppFlags //flags live in appflags.go

	app.Action = func(c *cli.Context) error {

		switch {
		case tlschk.CertFile != "" && tlschk.KeyFile != "":
			checkKeyPair()
		case tlschk.CertFile != "":
			_, _, ASN1certs := processCerts()
			if tlschk.Output == "json" {
				printJSONCert(ASN1certs)
			} else {
				for _, cert := range ASN1certs {
					tlschk.PrintText(cert)
				}
			}
		case tlschk.KeyFile != "":
			_, publicKey := processKey()
			keyModulusHash := extractModulus(publicKey)
			if tlschk.Output == "json" {
				printJSONKey(publicKey)
			} else {
				fmt.Println("Private key modulus SHA1 hash:", hashMaterial(keyModulusHash))
			}
		}

		return nil
	}

	app.Run(os.Args)

}
