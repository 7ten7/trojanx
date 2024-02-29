package test

import (
	"context"
	"crypto/tls"
	"github.com/kallydev/trojanx"
	"github.com/sirupsen/logrus"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

func Test_Main(t *testing.T) {
	go func() {
		server := &http.Server{
			Addr:         "127.0.0.1:80",
			ReadTimeout:  3 * time.Second,
			WriteTimeout: 3 * time.Second,
		}
		server.SetKeepAlivesEnabled(false)
		http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
			defer request.Body.Close()
			logrus.Debugln(request.RemoteAddr, request.RequestURI)
			host, _, _ := net.SplitHostPort(request.Host)
			switch host {
			default:
				writer.Header().Set("Connection", "close")
				writer.Header().Set("Referrer-Policy", "no-referrer")
				http.Redirect(writer, request, "https://www.baidu.com/", http.StatusFound)
			}
		})
		if err := server.ListenAndServe(); err != nil {
			log.Fatalln(err)
		}
	}()
	signed, _ := generateSelfSigned()
	srv := trojanx.NewServer(context.Background(), &trojanx.Config{
		Host:     net.IPv4zero.String(),
		Password: "password",
		Port:     443,
		TLSConfig: &trojanx.TLSConfig{
			MinVersion:  tls.VersionTLS13,
			MaxVersion:  tls.VersionTLS13,
			Certificate: signed,
		},
		ReverseProxyConfig: &trojanx.ReverseProxyConfig{
			Scheme: "http",
			Host:   "127.0.0.1",
			Port:   80,
		},
	})
	srv.ConnectHandler = func(ctx context.Context) bool {
		return true
	}
	srv.ErrorHandler = func(ctx context.Context, err error) {
		logrus.Errorln(err)
	}
	if err := srv.Run(); err != nil {
		logrus.Fatalln(err)
	}
}
