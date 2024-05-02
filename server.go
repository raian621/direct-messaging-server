package main

import (
	"fmt"
	"log"
	"net/http"
)

func NewServer(addr string, port int) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		fmt.Fprintln(w, "healthy")
	})

	AttachHandlers(mux)

	return &http.Server{
		Addr:    fmt.Sprintf("%s:%d", addr, port),
		Handler: mux,
	}
}

func StartServer(server *http.Server, certfile, keyfile string) {
	log.Printf("Server listening on https://%s\n", server.Addr)

	if err := server.ListenAndServeTLS(certfile, keyfile); err != nil {
		log.Fatal(err)
	}
}
