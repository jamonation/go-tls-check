package tlschk

import (
	"crypto/x509"
	"fmt"

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
