package eapi

import (
	"context"
	"fmt"
	"net/http"
	"path"
	"strings"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/immesys/wave/eapi/pb"
	"google.golang.org/grpc"
)

func allowCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			if r.Method == "OPTIONS" && r.Header.Get("Access-Control-Request-Method") != "" {
				preflightHandler(w, r)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}

func preflightHandler(w http.ResponseWriter, r *http.Request) {
	headers := []string{"Content-Type", "Accept"}
	w.Header().Set("Access-Control-Allow-Headers", strings.Join(headers, ","))
	methods := []string{"GET", "HEAD", "POST", "PUT", "DELETE"}
	w.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ","))
	glog.Infof("preflight request for %s", r.URL.Path)
	return
}

func serveSwagger(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, ".swagger.json") {
		http.NotFound(w, r)
		return
	}

	p := strings.TrimPrefix(r.URL.Path, "/swagger/")
	p = path.Join("swagger", p)
	http.ServeFile(w, r, p)
}

func runHTTPserver(dialaddr string, listenaddr string) {

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := http.NewServeMux()
	gw := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	err := pb.RegisterWAVEHandlerFromEndpoint(ctx, gw, dialaddr, opts)
	if err != nil {
		panic(err)
	}

	mux.HandleFunc("/swagger/", serveSwagger)
	mux.Handle("/", gw)
	s := &http.Server{
		Addr:    listenaddr,
		Handler: allowCORS(mux),
	}

	if err := s.ListenAndServe(); err != http.ErrServerClosed {
		fmt.Printf("HTTP server failed to listen: %v\n", err)
		panic(err)
	}
}
