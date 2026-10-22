package server

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed static/*
var dashboardFS embed.FS

func (s *Server) mountDashboard(mux *http.ServeMux) {
	sub, err := fs.Sub(dashboardFS, "static")
	if err != nil {
		s.log.Error("dashboard embed", "err", err)
		return
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard/", http.StatusFound)
	})
	mux.Handle("/dashboard/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serve index for /dashboard/
		p := strings.TrimPrefix(r.URL.Path, "/dashboard/")
		if p == "" || p == "/" {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/" + p
		fileServer.ServeHTTP(w, r)
	}))
}
