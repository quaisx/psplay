package main

import (
	"flag"
	"log"
	"time"
)

func main() {

	organization := flag.String("org", "ECMA Corporation", "Organization name for which to generate the certificate")
	dnsname := flag.String("dnsname", "localhost", "DNS name for the server serving this certificate")
	expires := flag.Int("expire", 0, "When this certificate expires in hours; 0 -> good for 99 years")
	help := flag.Bool("help", false, "Help")

	flag.Parse()

	if *help == true {
		flag.PrintDefaults()
		return
	}

	var notAfter time.Time
	if *expires > 0 {
		notAfter = time.Now().Add(time.Duration(*expires * time.Now().Hour()))
	} else {
		notAfter = time.Now().AddDate(99, 0, 0)
	}
	cipher := new(Cipher)
	if cipher.Generate(*organization, *dnsname, notAfter) {
		log.Println("Successfully generated cert.pem(+public key) and private.pem")
	} else {
		log.Println("Failed to generate cert.pem and private.pem")
	}
	// Verify with: openssl x509 -in cert.pem -text

}
