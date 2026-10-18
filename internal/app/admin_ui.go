package app

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed admin_ui/*
var adminUIFS embed.FS

func handleAdminUI(w http.ResponseWriter, r *http.Request) {
	sub, err := fs.Sub(adminUIFS, "admin_ui")
	if err != nil {
		http.Error(w, "embed error", 500)
		return
	}
	path := r.URL.Path
	if path == "/admin" {
		w.Header().Set("Location", "admin/")
		w.WriteHeader(http.StatusMovedPermanently)
		return
	}
	if path == "/admin/" || path == "/login" || path == "/register" || path == "/dashboard" || path == "/console" {
		path = "index.html"
	} else if strings.HasPrefix(path, "/admin/") {
		path = path[len("/admin/"):]
	} else {
		path = strings.TrimPrefix(path, "/")
	}
	f, err := sub.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	stat, _ := f.Stat()
	data := make([]byte, stat.Size())
	f.Read(data)
	switch {
	case len(path) > 5 && path[len(path)-5:] == ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case len(path) > 3 && path[len(path)-3:] == ".js":
		w.Header().Set("Content-Type", "application/javascript")
	case len(path) > 4 && path[len(path)-4:] == ".css":
		w.Header().Set("Content-Type", "text/css")
	case strings.HasSuffix(path, ".zip"):
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=\"gemini-cookie-sync.zip\"")
	default:
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Write(data)
}
