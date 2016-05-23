package tlschk

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"

	"github.com/fatih/color"
)

const LIGHT_VERTICAL_BAR = "\u2758"
const ARROW_DOWN_RIGHT = "\u2937"
const EMOJI_KEY = "\U0001f511"
const EMOJI_LOCK = "\U0001f512"

var label = color.New(color.FgRed, color.Bold).SprintFunc()
var warning = color.New(color.FgRed, color.Bold, color.Underline)

func printField(prefix string, field string, value interface{}) {
	// Nasty hard-coded paddings. These should be calculated based on the
	// width of the longest field name.
	fmt.Printf("%-5s%-24s\t%s\n", prefix, label(field), value)
}

func printDefaultField(field string, value interface{}) {
	printField(LIGHT_VERTICAL_BAR, field, value)
}

func printDefaultFieldWithEmoji(emoji string, field string, value interface{}) {
	printField(LIGHT_VERTICAL_BAR+" "+emoji, field, value)
}

func printSignerField(field string, value interface{}) {
	printField(ARROW_DOWN_RIGHT, field, value)
}

func parseCerts(certs []*x509.Certificate, InsecureSkipVerify bool) {
	chainLen := len(certs)
	for i, cert := range certs {
		PrintCert(i, *cert, chainLen, InsecureSkipVerify, false)
	}
}

func hashMaterial(material string) string {
	h := sha1.New()
	h.Write([]byte(material))
	shaSum := h.Sum(nil)
	hash := hex.EncodeToString(shaSum)
	return hash
}

func stringifyModulus(pubKey interface{}) string {
	var stringModulus string

	// need this type assertion to handle empty interface{}
	switch modulus := pubKey.(type) {
	case *rsa.PublicKey:
		stringModulus = modulus.N.String()
	case *big.Int:
		stringModulus = modulus.String()
	}
	return stringModulus
}

func PrintCert(i int, cert interface{}, chainLen int, InsecureSkipVerify bool, isFile bool) {

	var c *x509.Certificate

	switch certificate := cert.(type) {
	case *x509.Certificate:
		c = certificate
	}

	pubKey := stringifyModulus(c.PublicKey)
	shaSum := hashMaterial(string(c.Raw))
	modSum := hashMaterial(pubKey)

	if !c.IsCA {
		printDefaultFieldWithEmoji(EMOJI_KEY, "Certificate for:", c.DNSNames)
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Issued by:", c.Issuer.CommonName)
	} else {
		fmt.Println(LIGHT_VERTICAL_BAR)
		// make this into a switch set of statements
		if i == chainLen-1 && InsecureSkipVerify == false {
			printDefaultFieldWithEmoji(EMOJI_LOCK, "Root CA:", c.Subject.CommonName)
		} else if InsecureSkipVerify == true {
			printDefaultFieldWithEmoji(EMOJI_LOCK, "Intermediate CA:", c.Subject.CommonName)
		} else {
			printDefaultFieldWithEmoji(EMOJI_LOCK, "Intermediate CA:", c.Subject.CommonName)
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

func PrintText(c x509.Certificate) {

	//pubKey := extractModulus(c.PublicKey)
	shaSum := hashMaterial(string(c.Raw))
	//modSum := hashMaterial(pubKey)

	if !c.IsCA {
		printDefaultFieldWithEmoji(EMOJI_KEY, "Certificate for:", c.Subject.CommonName)
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		//printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Issued by:", c.Issuer.CommonName)
	} else {
		fmt.Println(LIGHT_VERTICAL_BAR)
		printDefaultFieldWithEmoji(EMOJI_LOCK, "Intermediate CA:", c.Subject.CommonName)
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		//printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Signed by:", c.Issuer.CommonName)
	}
}

func CheckCerts(conn *tls.Conn, HostName string, ServerName string, InsecureSkipVerify bool) {

	connTLSVersion := conn.ConnectionState().Version
	connCipherSuite := conn.ConnectionState().CipherSuite

	fmt.Println("\nConnected to", HostName, "with protocol:", TLSVersions[connTLSVersion])
	fmt.Println("Negotiated cipher suite:", CipherSuiteMap[connCipherSuite], "\n")

	if InsecureSkipVerify == false { // default behaviour unless -insecure flag is used
		err := conn.VerifyHostname(ServerName)
		if err != nil {
			fmt.Println("Bad ServerName: " + err.Error())
			conn.Close()
			os.Exit(1)
		}
		parseCerts(conn.ConnectionState().VerifiedChains[0], InsecureSkipVerify)
	} else { // use unverified cert chain, e.g. when connecting with -insecure
		warning.Println("WARNING: -noverify option specified. Only examining certificates sent by the remote server.\n")
		parseCerts(conn.ConnectionState().PeerCertificates, InsecureSkipVerify)
	}

}
