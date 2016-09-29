package tlschk

import (
	//"crypto/sha1"
	//"fmt"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const keyFile string = "tests/123.abc.key"
const certsFile string = "tests/123.abc.crt"
const keyPrivateHash string = "a27b68018dee84ec673a698fbc9be5c41f4b2a3d"
const keyFileHash string = "98cec43a472f5b2690a4021cb32de5466976bac4"
const keyModulus string = "28384459675537127912299868804778278678011770591741836911449145073239696167072542121861014361412485421585497137946160321965966110400930629450366827743994617159616099354794876259842300496822375130345502865640874307333282148898375197797420032024319395269992222806552964650191828841081057265236485458774970624386144072887377859118547886127347444325353522401564595453714487567574842715975318195325249128164674714260583097196447438137138280196960550452002482924607124201327875361739233781950148169506124707701059572714687988527033986815235890537266279055524898172368100142103785622258237600093465874273586311508546993647061"

func TestReadFile(t *testing.T) {
	_, err := readFile(keyFile)
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestParseCert(t *testing.T) {
	bytes, _ := readFile(certsFile)
	certs, _ := pem.Decode(bytes)
	_, err := parseCert(certs)
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestDecodeKey(t *testing.T) {
	var k KeyContainer
	k.PrivateKey.Bytes, _ = readFile(keyFile)
	_, err := k.decodeKey()
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestDecodeCerts(t *testing.T) {
	var k KeyContainer
	k.PublicKeys.Bytes, _ = readFile(certsFile)
	_, err := k.decodeCerts()
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestExtractModulusPrivate(t *testing.T) {
	keyBytes, _ := readFile(keyFile)
	key, _ := pem.Decode(keyBytes)
	keyX509, _ := x509.ParsePKCS1PrivateKey(key.Bytes)
	var actual string = ExtractModulus(&keyX509.PublicKey)
	var expected string = keyModulus
	if actual != expected {
		t.Errorf("Incorrect private key modulus")
	}
}

func TestExtractModulusPublic(t *testing.T) {
	certsBytes, _ := readFile(certsFile)
	cert, _ := pem.Decode(certsBytes)
	certX509, _ := x509.ParseCertificate(cert.Bytes)
	var actual string = ExtractModulus(certX509.PublicKey)
	var expected string = keyModulus
	if actual != expected {
		t.Errorf("Incorrect public key modulus")
	}
}

func TestHashMaterial(t *testing.T) {
	bytes, _ := readFile(keyFile)
	hash := HashMaterial(string(bytes))
	if hash != keyFileHash {
		t.Errorf("Failed to hash %s.\nExpected SHA1:\t%s\nActual SHA1:\t%s", keyFile, keyFileHash, hash)
	}
}

func TestProcessKey(t *testing.T) {
	var k KeyContainer
	k, err := ProcessKey(k, keyFile)
	if err != nil {
		t.Errorf(err.Error())
	}
}

func TestProcessCerts(t *testing.T) {
	var k KeyContainer
	k, err := ProcessCerts(k, certsFile)
	if err != nil {
		t.Errorf(err.Error())
	}
}
