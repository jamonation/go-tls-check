package tlschk

import (
	//"crypto/x509"


	//"github.com/fatih/color"
	//"fmt"
	"testing"
)

//var keyFile string = "tests/123.abc.key"
var certFile string = "tests/123.abc.crt"

func TestPrintText(t *testing.T) {
	var k KeyContainer
	var err error
	k, err = ProcessCerts(k, certFile)
	if err != nil {
		t.Errorf(err.Error())
	}	
	c := k.PublicKeys.LocalCertificates[0]
	PrintText(*c)
}

func TestPrintKeyAndCerts(t *testing.T) {
	var k KeyContainer
	var err error
	k, err = ProcessCerts(k, certFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	k, err = ProcessKey(k, keyFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	PrintKeyAndCerts(k, "")
	PrintKeyAndCerts(k, "json")
}
