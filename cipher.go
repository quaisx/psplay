package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

type Cipher struct {
	pk   *ecdsa.PrivateKey
	sn   *big.Int
	der  []byte
	cert []byte
	pem  []byte
}

func (c *Cipher) genKey() (status bool) {
	var e error
	status = true
	c.pk, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		log.Printf("genKey failed: %v", e)
		status = false
	} else {
		log.Printf("genKey success: %X%X", c.pk.X, c.pk.Y)
	}
	return
}

func (c *Cipher) genSN() (status bool) {
	var e error
	status = true
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	c.sn, e = rand.Int(rand.Reader, serialNumberLimit)
	if e != nil {
		log.Printf("genSN failed: %v", e)
		status = false
	} else {
		log.Printf("genSN successs: %X", c.sn)
	}
	return
}

func (c *Cipher) genCertDER(organization string, dnsname string, validAfter time.Time) (status bool) {
	var e error
	status = true
	template := x509.Certificate{
		SerialNumber: c.sn,
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		DNSNames:  []string{dnsname},
		NotBefore: time.Now(),
		NotAfter:  validAfter,

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	c.der, e = x509.CreateCertificate(rand.Reader, &template, &template, &c.pk.PublicKey, c.pk)
	if e != nil {
		log.Fatalf("genCertDER (certificate in DER encoding) failed: %v", e)
		status = false
	}
	return
}

func (c *Cipher) genCert() (status bool) {
	status = true
	c.cert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der})
	if c.cert == nil {
		log.Println("genCert failed - certificate is nil")
		status = false
		return
	}
	if e := os.WriteFile("cert.pem", c.cert, 0644); e != nil {
		log.Printf("genCert failed to write to cert.pem file: %v", e)
		status = false
	} else {
		log.Printf("genCert success: created %q", "cert.pem")
	}
	return
}

func (c *Cipher) genPK() (status bool) {
	var e error
	status = true
	privBytes, e := x509.MarshalPKCS8PrivateKey(c.pk)
	if e != nil {
		log.Printf("genPK failed to marshal private key to PKCS8: %v", e)
		status = false
		return
	}
	c.pem = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if c.pem == nil {
		log.Println("genPK failed to encode key to PEM")
		status = false
		return
	}
	if e = os.WriteFile("private.pem", c.pem, 0600); e != nil {
		log.Printf("genPK failed to write to %q: %v", "private.pem", e)
		status = false
	} else {
		log.Printf("genPK successfully wrote to %q", "private.pem")
	}
	return
}

func (c *Cipher) Generate(organization string, dnsname string, validAfter time.Time) (status bool) {
	status = false
	if c.genKey() {
		if c.genSN() {
			if c.genCertDER(organization, dnsname, validAfter) {
				if c.genCert() {
					if c.genPK() {
						log.Println("Generate successfully generated certificate and private key")
						status = true
					} else {
						log.Println("Generate failed to generate private key")
					}
				} else {
					log.Println("Generate failed to generate certificate")
				}
			} else {
				log.Println("Generate failed to generate DER encoded certificate")
			}
		} else {
			log.Println("Generate failed to generate certificate's serial number")
		}
	} else {
		log.Println("Generate failed to generate private/public key pair")
	}
	return
}
