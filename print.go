package tlschk

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/fatih/color"
)

const lightVerticalBar = "\u2758" // vertical bar
const arrowDownRight = "\u2937"   // down right arrow
const emojiKey = "\U0001f511"     // key
const emojiLock = "\U0001f512"    // lock

var label = color.New(color.FgRed, color.Bold).SprintFunc()
var warning = color.New(color.FgRed, color.Bold, color.Underline)

func printField(prefix string, field string, value interface{}) {
	// Nasty hard-coded paddings. These should be calculated based on the
	// width of the longest field name.
	fmt.Printf("%-5s%-24s\t%s\n", prefix, label(field), value)
}

func printDefaultField(field string, value interface{}) {
	printField(lightVerticalBar, field, value)
}

func printDefaultFieldWithemoji(emoji string, field string, value interface{}) {
	printField(lightVerticalBar+" "+emoji, field, value)
}

func printSignerField(field string, value interface{}) {
	printField(arrowDownRight, field, value)
}

// PrintText prints out specific fields of formatted ASN1 certificate data
func PrintText(c x509.Certificate) {
	pubKey := ExtractModulus(c.PublicKey)
	shaSum := HashMaterial(string(c.Raw))
	modSum := HashMaterial(pubKey)

	if !c.IsCA {
		printDefaultFieldWithemoji(emojiKey, "Certificate for:", c.DNSNames)
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Issued by:", c.Issuer.CommonName)
	} else {
		fmt.Println(lightVerticalBar)
		if c.Subject.CommonName == c.Issuer.CommonName {
			printDefaultFieldWithemoji(emojiLock, "ROOT CA:", c.Subject.CommonName)
		} else {
			printDefaultFieldWithemoji(emojiLock, "Intermediate CA:", c.Subject.CommonName)
		}
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Signed by:", c.Issuer.CommonName)
	}
}

// PrintKeyAndCerts prints matching or unmatching certificates and keys
func PrintKeyAndCerts(k KeyContainer, Output string) {
	privateKeyModulus := k.PrivateKey.Key.N
	matchedCerts := k.PrivateKey.KeyJSON.MatchedCerts
	unmatchedCerts := k.PrivateKey.KeyJSON.UnmatchedCerts
	switch {
	case Output == "json":
		for _, cert := range k.PublicKeys.LocalCertificates {
			publicKeyModulus := ExtractModulus(cert.PublicKey)
			certModulusHash := HashMaterial(ExtractModulus(cert.PublicKey))
			certJSON := CertJSON{
				CommonName:      cert.Subject.CommonName,
				SerialNumber:    cert.SerialNumber,
				Issuer:          cert.Issuer.CommonName,
				IsCA:            cert.IsCA,
				NotBefore:       cert.NotBefore,
				NotAfter:        cert.NotAfter,
				DNSNames:        cert.DNSNames,
				EmailAddresses:  cert.EmailAddresses,
				IPAddresses:     cert.IPAddresses,
				SHA1Fingerprint: HashMaterial(string(cert.Raw)),
				ModulusSHA1:     certModulusHash,
				Filename:        CertFile,
			}
			if publicKeyModulus == privateKeyModulus.String() {
				matchedCerts = append(matchedCerts, certJSON)
			} else {
				unmatchedCerts = append(unmatchedCerts, certJSON)
			}
		}
		k.PrivateKey.KeyJSON.MatchedCerts = matchedCerts
		k.PrivateKey.KeyJSON.UnmatchedCerts = unmatchedCerts
		k.PrivateKey.KeyJSON.ModulusSHA1 = HashMaterial(k.PrivateKey.Key.N.String())
		k.PrivateKey.KeyJSON.Filename = KeyFile
		b, err := json.MarshalIndent(k.PrivateKey.KeyJSON, "", "  ")
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		fmt.Println(string(b))
	case Output != "json":
		for _, cert := range k.PublicKeys.LocalCertificates {
			publicKeyModulus := ExtractModulus(cert.PublicKey)
			if publicKeyModulus == privateKeyModulus.String() {
				fmt.Println("\nPublic and private keys MATCH")
			} else {
				fmt.Println("\nPublic and private keys DO NOT MATCH")
			}
			fmt.Println("Private key modulus SHA1 hash:", HashMaterial(privateKeyModulus.String()))
			fmt.Println("Public cert modulus SHA1 hash:", HashMaterial(publicKeyModulus))
			PrintText(*cert)
		}
	}
}
