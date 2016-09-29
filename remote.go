package tlschk

import (
	"crypto/tls"
	"fmt"
)

// CheckCerts connects to a remote Host and can validate a cert chain
// Or simply display the server's certificate(s)
func CheckCerts(conn *tls.Conn, k KeyContainer) (KeyContainer, error) {
	connTLSVersion := conn.ConnectionState().Version
	connCipherSuite := conn.ConnectionState().CipherSuite

	if Output != "json" {
		fmt.Println("\nConnected to", Host, "with protocol:", TLSVersions[connTLSVersion])
		fmt.Println("Negotiated cipher suite:", CipherSuiteMap[connCipherSuite])
	}

	if InsecureSkipVerify == false { // default behaviour unless -insecure flag is used
		err := conn.VerifyHostname(Server)
		if err != nil {
			return k, err
		}
		k.PublicKeys.VerifiedChains = conn.ConnectionState().VerifiedChains[0]
	} else { // use unverified cert chain, e.g. when connecting with -insecure
		k.PublicKeys.PeerCertificates = conn.ConnectionState().PeerCertificates
	}
	return k, nil
}
