package trojanx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/kallydev/trojanx/protocol"
	"github.com/sirupsen/logrus"
	"net"
)

type (
	ConnectHandler        = func(ctx context.Context) bool
	AuthenticationHandler = func(ctx context.Context, reqHash string, serverHash string) bool
	RequestHandler        = func(ctx context.Context, request protocol.Request) bool
	ForwardHandler        = func(ctx context.Context, upload, download int64) bool
	ErrorHandler          = func(ctx context.Context, err error)
)

func DefaultConnectHandler(ctx context.Context) bool {
	return true
}

func DefaultAuthenticationHandler(ctx context.Context, reqHash string, serverHash string) bool {
	switch reqHash {
	case sha224(serverHash):
		return true
	default:
		return false
	}
}

func sha224(password string) string {
	hash224 := sha256.New224()
	hash224.Write([]byte(password))
	sha224Hash := hash224.Sum(nil)
	return hex.EncodeToString(sha224Hash)
}

func DefaultRequestHandler(ctx context.Context, request protocol.Request) bool {
	var remoteIP net.IP
	if request.AddressType == protocol.AddressTypeDomain {
		tcpAddr, err := net.ResolveTCPAddr("tcp", request.DescriptionAddress)
		if err != nil {
			logrus.Errorln(err)
			return false
		}
		remoteIP = tcpAddr.IP
	} else {
		remoteIP = net.ParseIP(request.DescriptionAddress)
	}
	if remoteIP.IsLoopback() || remoteIP.IsLinkLocalUnicast() || remoteIP.IsLinkLocalMulticast() || remoteIP.IsPrivate() {
		return false
	}
	return true
}

func DefaultErrorHandler(ctx context.Context, err error) {
	logrus.Errorln(err)
}
