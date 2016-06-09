package tlschk

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net"
	"time"
)

type CertList struct {
	PeerCertificates  []*x509.Certificate
	VerifiedChains    []*x509.Certificate
	LocalCertificates []*x509.Certificate
	Bytes             []byte
}

// KeyJSON is a container for key & associated (or not) certs
type KeyJSON struct {
	ModulusSHA1    string `json:"PrivateKeySHA1Modulus"`
	Filename       string `json:"PrivateKeyFilename"`
	MatchedCerts   []CertJSON
	UnmatchedCerts []CertJSON
}

// CertJSON contains some selected ASN1 fields for json output
// willing to add more ASN1 fields, or all if requested
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
	Filename        string
}

// PrivateKey contains the rsa key, raw byte version, and
// a JSON representation of the public key & associated cert(s)
type PrivateKey struct {
	Key     *rsa.PrivateKey
	Bytes   []byte
	Hash    string `json:"public key hash"`
	KeyJSON KeyJSON
}

// KeyContainer is the main struct that contains both public and private keys
type KeyContainer struct {
	PublicKeys CertList
	PrivateKey PrivateKey
}
