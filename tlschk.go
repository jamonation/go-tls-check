package tlschk

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
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

func readFile(f string) (b []byte, err error) {
	file, err := os.Open(f)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}
	return data, err
}

// HashMaterial returns hex encoded SHA1 sums of input strings
func hashMaterial(material string) string {
	h := sha1.New()
	h.Write([]byte(material))
	shaSum := h.Sum(nil)
	hash := hex.EncodeToString(shaSum)
	return hash
}

// parse a PEM block and return an x509 certificate
func parseCert(certBlock *pem.Block) (*x509.Certificate, error) {
	decodedCertASN1, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println("Unable to parse public certificate. Error was:")
		return nil, err
	}
	return decodedCertASN1, nil
}

// decodeKey decodes raw pem bytes, and then returns the rsa private key
func (k *KeyContainer) decodeKey() (key *rsa.PrivateKey, err error) {
	decodedKeyBytes, _ := pem.Decode(k.PrivateKey.Bytes)
	if decodedKeyBytes != nil {
		key, err = x509.ParsePKCS1PrivateKey(decodedKeyBytes.Bytes)
		if err != nil {
			fmt.Println("Unable to parse private key. Error was:")
			return nil, err
		}
	} else {
		err = errors.New("Could not find a private key")
		return key, err
	}
	return key, nil
}

func (k *KeyContainer) decodeCerts() (certs []*x509.Certificate, err error) {
	certBlock, rest := pem.Decode(k.PublicKeys.Bytes)
	if certBlock != nil {
		certASN1, err := parseCert(certBlock)
		if err != nil {
			return nil, err
		}
		certs = append(certs, certASN1)

		for len(rest) > 0 {
			certBlock, rest = pem.Decode(rest)
			certASN1, err = parseCert(certBlock)
			if err != nil {
				return nil, err
			}
			certs = append(certs, certASN1)
		}
	} else {
		err = errors.New("Could not parse certificate(s)")
		return nil, err
	}

	return certs, nil

}

// ProcessKey reads and returns a private key from the filesystem
func ProcessKey(k KeyContainer) (KeyContainer, error) {
	var err error
	k.PrivateKey.Bytes, err = readFile(KeyFile)
	if err != nil {
		return k, err
	}
	k.PrivateKey.Key, err = k.decodeKey()
	if err != nil {
		return k, err
	}
	k.PrivateKey.Hash = hashMaterial(k.PrivateKey.Key.N.String())
	return k, nil
}

// ProcessCerts reads and returns an array of certificates
func ProcessCerts(k KeyContainer) (KeyContainer, error) {
	var err error
	k.PublicKeys.Bytes, err = readFile(CertFile)
	if err != nil {
		return k, err
	}
	k.PublicKeys.LocalCertificates, err = k.decodeCerts()
	if err != nil {
		return k, err
	}
	for _, cert := range k.PublicKeys.LocalCertificates {
		fmt.Println(cert.Subject.CommonName)
	}
	return k, nil
}
