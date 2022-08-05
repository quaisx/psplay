package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := flag.String("addr", "localhost", "HTTPS server address")
	port := flag.Int("port", 8888, "HTTPS server port")
	certFile := flag.String("cert_pem", "../cert/cert.pem", "X509 CA certificate .pem file")
	flag.Parse()

	cert, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatal(err)
	}
	certPool := x509.NewCertPool()
	if ok := certPool.AppendCertsFromPEM(cert); !ok {
		log.Fatalf("Failed to parse %s as X509 CA certificate", *certFile)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
	}
	address := fmt.Sprintf("%s:%d", *addr, *port)
	endpoint := fmt.Sprintf("https://%s/client/", address)
	bcsReq, _ := http.NewRequest("GET", endpoint, nil)
	q := bcsReq.URL.Query()
	q.Add("client_id", "12345")
	bcsReq.URL.RawQuery = q.Encode()

	bcsResp, err := client.Do(bcsReq)
	if err != nil {
		log.Printf("ERROR: %v", err)
	}
	if bcsResp.StatusCode == 200 {
		html, err := io.ReadAll(bcsResp.Body)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("STATUS:   %v\n", bcsResp.Status)
		fmt.Printf("RESPONSE: %s\n", string(html))
	}
	bcsResp.Body.Close()

}
