package tlschk

import (
	"fmt"
	"crypto/tls"
	"os"
)

func CheckCerts(conn *tls.Conn, ServerName string) {
	
	connTLSVersion := conn.ConnectionState().Version
	connCipherSuite := conn.ConnectionState().CipherSuite

	fmt.Println("Connected using", TLSVersions[connTLSVersion], "with", CipherSuiteMap[connCipherSuite], "\n")

	err := conn.VerifyHostname(ServerName)
	if err != nil {
		fmt.Println("Bad ServerName: " + err.Error())
		conn.Close()
		os.Exit(1)
	}
	
	//certs := conn.ConnectionState().PeerCertificates
	verified := conn.ConnectionState().VerifiedChains[0]
	
	for i, c := range verified {
		if !c.IsCA {
			fmt.Println("❘ 🔑  \x1b[31;1mCertificate for:\x1b[0m", c.DNSNames)
			fmt.Println("❘ 🕕 \t\x1b[31;1mValid until\x1b[0m", c.NotAfter)
			fmt.Println("⤷ \t\x1b[31;1mIssued by:\x1b[0m", c.Issuer.CommonName)

		} else {
			fmt.Println("❘\n❘ 🔒  \x1b[31;1mParent CA:\x1b[0m", c.Subject.CommonName)
			fmt.Println("❘ 🕕 \t\x1b[31;1mValid until\x1b[0m", c.NotAfter)
			if !(i == len(verified) - 1) {
				fmt.Println("⤷ 🖊\t\x1b[31;1mSigned by:\x1b[0m", c.Issuer.CommonName)
			} else {
				fmt.Println("⤷ 🖊\t\x1b[31;1mRoot Self-Signed by:\x1b[0m", c.Issuer.CommonName)
			}
		}

	}

	/*
	for _, cert := range certs {
		if !cert.IsCA {
			fmt.Println(cert.DNSNames, "issued by:", cert.Issuer.CommonName)
		} else {
			fmt.Println(cert.Subject.CommonName, "signed by:", cert.Issuer.CommonName)
		}
		fmt.Println("Valid until", cert.NotAfter, "\n")
	}
        */
}
