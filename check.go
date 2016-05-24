package tlschk

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/fatih/color"
	"math/big"
	"os"
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
		fmt.Printf("Found invalid or non-key material in %s:\n", KeyFile)
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

// parse a PEM block and return an x509 certificate
func parseCert(certBlock *pem.Block) *x509.Certificate {
	decodedCertASN1, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("Unable to parse public certificate. Error was:")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	return decodedCertASN1
}

// ParseRemoteCerts is a dumb function, should be refactored into PrintText
// just iterates slice of cert pointers and dispatches to PrintCert
func ParseRemoteCerts(certs []*x509.Certificate) {
	chainLen := len(certs)
	for i, cert := range certs {
		PrintCert(i, *cert, chainLen)
	}
}

// ProcessCerts reads a file from the filesystem
// - then it splits raw bytes into separate pem.Blocks
// - then it extracts the parsed x509.Certificate for each block
func ProcessCerts() ([]byte, []interface{}, []*x509.Certificate) {
	var cert *pem.Block
	var certASN1 *x509.Certificate

	//var splitRawCerts [][]byte
	var ASN1certs []*x509.Certificate
	var publicKeys []interface{}

	rawCerts := readFile(CertFile)
	rest := rawCerts

	for len(rest) > 0 {
		cert, rest = decodeMaterial(rest)
		certASN1 = parseCert(cert)
		ASN1certs = append(ASN1certs, certASN1)
		publicKey := ExtractModulus(certASN1.PublicKey)
		publicKeys = append(publicKeys, publicKey)
	}

	return rawCerts, publicKeys, ASN1certs
}

// ProcessKey reads and returns a private key from the filesystem
func ProcessKey() ([]byte, *big.Int) {
	var privateKey *rsa.PrivateKey
	var publicKey *big.Int

	rawKey := readFile(KeyFile)
	privateKey = decodeKey(rawKey)
	publicKey = privateKey.PublicKey.N
	return rawKey, publicKey
}

// CheckKeyPair compares a private key with n certificates to see if they match
func CheckKeyPair() {
	_, keyPublicKey := ProcessKey()
	_, _, ASN1Certs := ProcessCerts()

	keyModulus := ExtractModulus(keyPublicKey)
	keyModulusHash := HashMaterial(keyModulus)

	switch {
	case Output == "text":
		for i := range ASN1Certs {
			certModulus := ExtractModulus(ASN1Certs[i].PublicKey)
			certModulusHash := HashMaterial(certModulus)
			if certModulus != keyModulus {
				fmt.Println("\nPublic and private keys DO NOT MATCH.")
			} else {
				fmt.Println("\nPublic and private keys MATCH")
			}
			fmt.Println("Private key modulus SHA1 hash:", keyModulusHash)
			fmt.Println("Public cert modulus SHA1 hash:", certModulusHash)
			PrintText(*ASN1Certs[i])
		}
	case Output == "json":

		keyJSON := KeyJSON{
			ModulusSHA1:    keyModulusHash,
			Filename:       KeyFile,
			MatchedCerts:   nil,
			UnmatchedCerts: nil,
		}

		for _, c := range ASN1Certs {
			certModulusHash := HashMaterial(ExtractModulus(c.PublicKey))
			cert := CertJSON{
				CommonName:      c.Subject.CommonName,
				SerialNumber:    c.SerialNumber,
				Issuer:          c.Issuer.CommonName,
				IsCA:            c.IsCA,
				NotBefore:       c.NotBefore,
				NotAfter:        c.NotAfter,
				DNSNames:        c.DNSNames,
				EmailAddresses:  c.EmailAddresses,
				IPAddresses:     c.IPAddresses,
				SHA1Fingerprint: HashMaterial(string(c.Raw)),
				ModulusSHA1:     certModulusHash,
				Filename:        CertFile,
			}

			if certModulusHash == keyModulusHash {
				keyJSON.MatchedCerts = append(keyJSON.MatchedCerts, cert)
			} else {
				keyJSON.UnmatchedCerts = append(keyJSON.UnmatchedCerts, cert)
			}
		}

		js, err := json.MarshalIndent(keyJSON, "", "  ")
		if err != nil {
			fmt.Println("ERROR MARSHALLING")
			os.Exit(1)
		}
		fmt.Println(string(js))
	}
	return
}

// HashMaterial returns hex encoded SHA1 sums of input strings
func HashMaterial(material string) string {
	h := sha1.New()
	h.Write([]byte(material))
	shaSum := h.Sum(nil)
	hash := hex.EncodeToString(shaSum)
	return hash
}

// ExtractModulus uses type assertion to get the modulus from a public or private key
// WHERE IS THE ERROR HANDLING!? Or, should this never be reached if there's no modulus?
func ExtractModulus(publicKey interface{}) string {
	var modulus string

	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		modulus = key.N.String()
	case *big.Int:
		modulus = key.String()
	}
	return modulus
}

// PrintCert ought to be merged into PrintText - they are pretty much duplicates
func PrintCert(i int, c x509.Certificate, chainLen int) {

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
		// make this into a switch set of statements
		if i == chainLen-1 && InsecureSkipVerify == false {
			printDefaultFieldWithemoji(emojiLock, "Root CA:", c.Subject.CommonName)
		} else if InsecureSkipVerify == true {
			printDefaultFieldWithemoji(emojiLock, "Intermediate CA:", c.Subject.CommonName)
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

// PrintJSONCert prints a certificate(s) as JSON
func PrintJSONCert(rawCerts []*x509.Certificate) {

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
			SHA1Fingerprint: HashMaterial(string(c.Raw)),
			ModulusSHA1:     HashMaterial(ExtractModulus(c.PublicKey)),
			Filename:        CertFile,
		})
	}
	jsonData, err := json.MarshalIndent(certs, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling json")
	}
	fmt.Println(string(jsonData))
}

// PrintJSONKey prints a private key modulus and path as JSON
func PrintJSONKey(publicKey *big.Int) {
	key := KeyJSON{
		ModulusSHA1: HashMaterial(publicKey.String()),
		Filename:    KeyFile,
	}
	jsonKey, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling private key into JSON:")
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Println(string(jsonKey))
}

// PrintText prints out specific fields of formatted ASN1 certificate data
func PrintText(c x509.Certificate) {
	pubKey := ExtractModulus(c.PublicKey)
	shaSum := HashMaterial(string(c.Raw))
	modSum := HashMaterial(pubKey)

	if !c.IsCA {
		printDefaultFieldWithemoji(emojiKey, "Certificate for:", c.Subject.CommonName)
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Issued by:", c.Issuer.CommonName)
	} else {
		fmt.Println(lightVerticalBar)
		printDefaultFieldWithemoji(emojiLock, "Intermediate CA:", c.Subject.CommonName)
		printDefaultField("Valid from:", c.NotBefore)
		printDefaultField("Valid until:", c.NotAfter)
		printDefaultField("Serial number:", c.SerialNumber)
		printDefaultField("SHA1 fingerprint:", shaSum)
		printDefaultField("Modulus SHA1:", modSum)
		printDefaultField("Signature algo:", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		printSignerField("Signed by:", c.Issuer.CommonName)
	}
}

// CheckCerts connects to a remote Host and can validate a cert chain
// Or simply display the server's certificate(s)
func CheckCerts(conn *tls.Conn) {
	var certs []*x509.Certificate
	connTLSVersion := conn.ConnectionState().Version
	connCipherSuite := conn.ConnectionState().CipherSuite

	fmt.Println("\nConnected to", Host, "with protocol:", TLSVersions[connTLSVersion])
	fmt.Println("Negotiated cipher suite:", CipherSuiteMap[connCipherSuite])

	if InsecureSkipVerify == false { // default behaviour unless -insecure flag is used
		err := conn.VerifyHostname(Server)
		if err != nil {
			fmt.Println("Bad Server Name: " + err.Error())
		}
		certs = conn.ConnectionState().VerifiedChains[0]
		if Output == "json" {
			PrintJSONCert(certs)
		} else {
			ParseRemoteCerts(certs)
		}
	} else { // use unverified cert chain, e.g. when connecting with -insecure
		certs = conn.ConnectionState().PeerCertificates
		warning.Printf("WARNING: -noverify option specified. Only examining certificates sent by the remote server.\n")
		ParseRemoteCerts(certs)
	}
}
