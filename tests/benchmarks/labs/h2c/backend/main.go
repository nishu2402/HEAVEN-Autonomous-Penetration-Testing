// HEAVEN h2c-smuggling lab — the BACKEND.
//
// A deliberately access-control-free HTTP/2-cleartext (h2c) server. It serves
// /admin openly and relies entirely on the front-end proxy to block it. Go's
// h2c.NewHandler answers BOTH the HTTP/1.1 "Upgrade: h2c" handshake (responding
// 101) and raw HTTP/2 prior-knowledge, which is exactly what lets a request
// tunnelled through the proxy reach this server directly.
package main

import (
	"fmt"
	"net/http"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// NOT a catch-all: unknown paths 404, so the detector's catch-all guard
		// (a random control path answering 2xx) does not suppress the finding.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintf(w, "backend ok: / (%s)\n", r.Proto)
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		// No authentication here on purpose: the proxy is supposed to guard it.
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "ADMIN PANEL (backend, unauthenticated) via %s\n", r.Proto)
	})
	handler := h2c.NewHandler(mux, &http2.Server{})
	srv := &http.Server{Addr: ":80", Handler: handler}
	_ = srv.ListenAndServe()
}
