package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	addr := ":9000"
	if v := os.Getenv("ADDR"); v != "" {
		addr = v
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "hello from intranet\npath=%s\nhost=%s\nremote=%s\n", r.URL.Path, r.Host, r.RemoteAddr)
	})
	log.Printf("local http service on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
