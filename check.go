package tlschk

import (
	"fmt"
	"crypto/tls"
	"os"
	"crypto/x509"
	"crypto/sha1"
	"encoding/hex"	
)


func parseCerts(certs []*x509.Certificate, InsecureSkipVerify bool) {
	chainLen := len(certs)
	for i, cert := range certs {
		printCert(i, cert, chainLen, InsecureSkipVerify)
	}
}


func printCert(i int, c *x509.Certificate, chainLen int, InsecureSkipVerify bool) {

	h := sha1.New()
	h.Write([]byte(c.Raw))
	shaSum := h.Sum(nil)

	if !c.IsCA {
		fmt.Println("❘ 🔑  \x1b[31;1mCertificate for:\x1b[0m", c.DNSNames)
		fmt.Println("❘    \x1b[31;1mValid from:\x1b[0m\t", c.NotBefore)
		fmt.Println("❘    \x1b[31;1mValid until:\x1b[0m\t", c.NotAfter)
		fmt.Println("❘    \x1b[31;1mSerial number:\x1b[0m\t", c.SerialNumber)
		fmt.Println("❘    \x1b[31;1mSHA1 fingerprint:\x1b[0m\t", hex.EncodeToString(shaSum))
		fmt.Println("❘    \x1b[31;1mSignature algo:\x1b[0m\t", SignatureAlgorithms[int(c.SignatureAlgorithm)])
		fmt.Println("⤷    \x1b[31;1mIssued by:\x1b[0m\t\t", c.Issuer.CommonName)

	} else {
		// make this into a switch set of statements
		if (i == chainLen - 1 && InsecureSkipVerify == false) {
			fmt.Println("❘\n❘ 🔒  \x1b[31;1mRoot CA:\x1b[0m", c.Subject.CommonName)
		} else if (InsecureSkipVerify == true) {
			fmt.Println("❘\n❘ 🔒  \x1b[31;1mIntermediate CA:\x1b[0m", c.Subject.CommonName)
		} else {
			fmt.Println("❘\n❘ 🔒  \x1b[31;1mIntermediate CA:\x1b[0m", c.Subject.CommonName)			
		}
		fmt.Println("❘    \x1b[31;1mValid from:\x1b[0m\t", c.NotBefore)
		fmt.Println("❘    \x1b[31;1mValid until:\x1b[0m\t", c.NotAfter)
		fmt.Println("❘    \x1b[31;1mSerial number:\x1b[0m\t", c.SerialNumber)
		fmt.Println("❘    \x1b[31;1mSHA1 fingerprint:\x1b[0m\t", hex.EncodeToString(shaSum))
		fmt.Println("❘    \x1b[31;1mSignature algo:\x1b[0m\t", SignatureAlgorithms[int(c.SignatureAlgorithm)])

		fmt.Println("⤷    \x1b[31;1mSigned by:\x1b[0m\t\t", c.Issuer.CommonName)
	}
}


func CheckCerts(conn *tls.Conn, HostName string, ServerName string, InsecureSkipVerify bool) {
	
	connTLSVersion := conn.ConnectionState().Version
	connCipherSuite := conn.ConnectionState().CipherSuite

	fmt.Println("\nConnected to", HostName, "with protocol:", TLSVersions[connTLSVersion])
	fmt.Println("Negotiated cipher suite:", CipherSuiteMap[connCipherSuite], "\n")
	
	if (InsecureSkipVerify == false) { // default behaviour unless -insecure flag is used
		err := conn.VerifyHostname(ServerName)
		if err != nil {
			fmt.Println("Bad ServerName: " + err.Error())
			conn.Close()
			os.Exit(1)
		}
		parseCerts(conn.ConnectionState().VerifiedChains[0], InsecureSkipVerify)
	} else { // use unverified cert chain, e.g. when connecting with -insecure
		fmt.Println("\x1b[31;1m\x1b[4;1mWARNING: -noverify option specified. Only examining certificates sent by the remote server.\x1b[0m\n")
		parseCerts(conn.ConnectionState().PeerCertificates, InsecureSkipVerify)
	}

}
