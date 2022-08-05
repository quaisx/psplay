package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "localhost", "HTTPS server address")
	port := flag.Int("port", 8888, "HTTPS Server port")
	certFile := flag.String("cert_pem", "../cert/cert.pem", "X509 certificate file")
	keyFile := flag.String("private_pem", "../cert/private.pem", "X509 private key file")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/client/", func(w http.ResponseWriter, req *http.Request) {
		q := req.URL.Query().Get("client_id")
		w.Header().Add("Content-Type", "text/plain")
		fmt.Fprintf(w, "Secure comminication over HTTPS with client id: %s", q)
	})
	address := fmt.Sprintf("%s:%d", *addr, *port)
	srv := &http.Server{
		Addr:    address,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionTLS13,
			PreferServerCipherSuites: true,
		},
	}

	log.Printf("HTTPS server is running on %s", address)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}
