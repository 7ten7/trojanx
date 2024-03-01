package trojanx

import "github.com/sirupsen/logrus"

type Option func(s *Server)

func WithLogger(l *logrus.Logger) Option {
	return func(s *Server) {
		s.logger = l
	}
}

func WithConfig(config *TrojanConfig) Option {
	return func(s *Server) {
		s.config = config
	}
}

func WithConnectHandler(handler connectHandler) Option {
	return func(s *Server) {
		s.connectHandler = handler
	}
}

func WhichAuthenticationHandler(handler authenticationHandler) Option {
	return func(s *Server) {
		s.authenticationHandler = handler
	}
}

func WhichRequestHandler(handler requestHandler) Option {
	return func(s *Server) {
		s.requestHandler = handler
	}
}

func WhichErrorHandler(handler errorHandler) Option {
	return func(s *Server) {
		s.errorHandler = handler
	}
}
