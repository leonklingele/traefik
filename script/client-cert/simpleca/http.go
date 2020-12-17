package simpleca

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
)

const (
	httpPort = 8081
)

// RegisterHTTPHandlers registers all required CA HTTP handlers (e.g. for the CRL).
func (ca *CA) RegisterHTTPHandlers() {
	crlPath := ca.CRLPath()
	route := "/" + crlPath
	log.Println("registering HTTP route", route)
	http.HandleFunc(route, func(res http.ResponseWriter, req *http.Request) {
		if _, err := res.Write(ca.crl); err != nil {
			log.Printf("failed to serve CRL: %v", err)
		}
	})
}

// ServeHTTP starts the HTTP CRL server.
func ServeHTTP() func() error {
	srv := &http.Server{Addr: fmt.Sprintf(":%d", httpPort)}
	go func() {
		log.Printf("starting HTTP server to serve CRL(s) on port %d…", httpPort)
		defer log.Printf("stopped HTTP server to serve CRL(s) on port %d…", httpPort)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()
	return func() error {
		return srv.Shutdown(context.Background())
	}
}
