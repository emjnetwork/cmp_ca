// Command cmp_ca starts a CMP (Certificate Management Protocol, RFC 4210) debug
// server backed by an in-memory CA.  It handles Initialization Requests (IR)
// and Key Update Requests (KUR), returning newly signed certificates without
// verifying Proof of Possession — intentionally, for debugging purposes.
//
// Usage:
//
//	cmp_ca [-addr :8080]
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/Edu171002/cmp_ca/ca"
	"github.com/Edu171002/cmp_ca/cmp"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	c, err := ca.New()
	if err != nil {
		log.Fatalf("create CA: %v", err)
	}

	fmt.Printf("CMP Debug CA ready\n")
	fmt.Printf("CA subject : %s\n", c.Certificate.Subject.CommonName)
	fmt.Printf("CA serial  : %s\n", c.Certificate.SerialNumber)
	fmt.Printf("Listening  : http://%s\n", *addr)
	fmt.Printf("\nCA certificate (PEM):\n%s\n", c.CertPEM())

	h := &cmp.Handler{CA: c}
	http.Handle("/", h)

	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatalf("ListenAndServe: %v", err)
	}
}
