package trojanx

import (
	"context"
	"crypto/tls"
	"github.com/kallydev/trojanx/internal/common"
	"github.com/kallydev/trojanx/internal/pipe"
	"github.com/kallydev/trojanx/internal/tunnel"
	"github.com/kallydev/trojanx/metadata"
	"github.com/kallydev/trojanx/protocol"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
)

type Server struct {
	ctx         context.Context
	config      *Config
	tcpListener net.Listener
	tlsListener net.Listener

	// TODO some callback functions
	ConnectHandler        ConnectHandler
	AuthenticationHandler AuthenticationHandler
	RequestHandler        RequestHandler
	ErrorHandler          ErrorHandler
	// TODO add a record callback handler
}

func (s *Server) run() error {
	var err error
	s.tcpListener, err = net.Listen("tcp", net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port)))
	if err != nil {
		return err
	}
	var tlsCertificates []tls.Certificate
	if s.config.TLSConfig != nil {
		tlsCertificates = append(tlsCertificates, s.config.TLSConfig.Certificate)
		s.tlsListener = tls.NewListener(s.tcpListener, &tls.Config{
			Certificates: tlsCertificates,
		})
	}
	for {
		var conn net.Conn
		if s.tlsListener == nil {
			conn, err = s.tcpListener.Accept()
		} else {
			conn, err = s.tlsListener.Accept()
		}
		if err != nil {
			s.ErrorHandler(s.ctx, err)
			continue
		}
		go s.Handle(conn)
	}
}

func (s *Server) Handle(conn net.Conn) {
	defer conn.Close()
	// TODO Not used for now
	ctx := metadata.NewContext(context.Background(), metadata.Metadata{
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
	})
	if !s.ConnectHandler(ctx) {
		return
	}
	token, err := protocol.GetToken(conn)
	if err != nil && token == "" {
		s.ErrorHandler(ctx, err)
		return
	}
	if !s.AuthenticationHandler(ctx, token, s.config.Password) {
		logrus.Debugln("authentication not passed", conn.RemoteAddr())
		if s.config.ReverseProxyConfig == nil {
			return
		}
		remoteURL := net.JoinHostPort(s.config.ReverseProxyConfig.Host, strconv.Itoa(s.config.ReverseProxyConfig.Port))
		dst, err := net.Dial("tcp", remoteURL)
		if err != nil {
			s.ErrorHandler(ctx, err)
			return
		}
		logrus.Debugln("reverse proxy policy", conn.RemoteAddr(), dst.LocalAddr())
		defer dst.Close()
		if _, err := dst.Write([]byte(token)); err != nil {
			s.ErrorHandler(ctx, err)
			return
		}
		go pipe.Copy(dst, conn)
		pipe.Copy(conn, dst)
		return
	}
	req, err := protocol.ParseRequest(conn)
	if err != nil {
		s.ErrorHandler(ctx, err)
		return
	}
	if req.Command == protocol.CommandUDP {
		s.relayPacketLoop(conn)
	} else if req.Command == protocol.CommandConnect {
		s.relayConnLoop(ctx, conn, req)
	}
}

func (s *Server) relayConnLoop(ctx context.Context, conn net.Conn, req *protocol.Request) {
	dst, err := net.Dial("tcp", net.JoinHostPort(req.DescriptionAddress, strconv.Itoa(req.DescriptionPort)))
	if err != nil {
		s.ErrorHandler(ctx, err)
		return
	}
	defer dst.Close()
	go pipe.Copy(dst, conn)
	pipe.Copy(conn, dst)
}

func (s *Server) relayPacketLoop(conn net.Conn) {
	udpConn, _ := net.ListenPacket("udp4", "")
	defer udpConn.Close()
	defer conn.Close()
	outbound := tunnel.UDPConn{udpConn.(*net.UDPConn)}
	inbound := tunnel.TrojanConn{conn}
	errChan := make(chan error, 2)
	copyPacket := func(a, b common.PacketConn) {
		for {
			buf := make([]byte, common.MaxPacketSize)
			n, metadata, err := a.ReadWithMetadata(buf)
			if err != nil {
				errChan <- err
				return
			}
			if n == 0 {
				errChan <- nil
				return
			}
			_, err = b.WriteWithMetadata(buf[:n], metadata)
			if err != nil {
				errChan <- err
				return
			}
		}
	}
	go copyPacket(&inbound, &outbound)
	go copyPacket(&outbound, &inbound)
	select {
	case err := <-errChan:
		if err != nil {
			logrus.Error(err)
		}
	}
}

func (s *Server) Run() error {
	errCh := make(chan error)
	go func() {
		errCh <- s.run()
	}()
	select {
	case err := <-errCh:
		return err
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}

func NewServer(ctx context.Context, config *Config) *Server {
	return &Server{
		ctx:                   ctx,
		config:                config,
		ConnectHandler:        DefaultConnectHandler,
		AuthenticationHandler: DefaultAuthenticationHandler,
		RequestHandler:        DefaultRequestHandler,
		ErrorHandler:          DefaultErrorHandler,
	}
}
