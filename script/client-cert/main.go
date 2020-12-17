package main

import (
	"flag"
	"log"

	"github.com/traefik/traefik/v2/script/client-cert/simpleca"
)

func main() {
	startHTTP := flag.Bool("http", false, "start CA HTTP server")
	flag.Parse()

	const writeFiles = true
	cas, err := simpleca.BasicRun(writeFiles)
	if err != nil {
		log.Fatal(err)
	}

	if *startHTTP {
		for _, ca := range cas {
			ca.RegisterHTTPHandlers()
		}

		serverShutdownFunc := simpleca.ServeHTTP()
		defer serverShutdownFunc()
		select {}
	}
}
