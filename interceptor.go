package grpceptortest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	grpc_testing "github.com/grpc-ecosystem/go-grpc-middleware/testing"
	testpb "github.com/grpc-ecosystem/go-grpc-middleware/testing/testproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"gotest.tools/v3/assert"
)

var (
	certPEM          []byte
	keyPEM           []byte
	errNilServerOpts error = errors.New("error server options can't be nil")
	errNilClientOpts error = errors.New("error client options can't be nil")
	errNilTestServer error = errors.New("error test server can't be nil")
	errNilTesting    error = errors.New("error testing can't be nil")
)

type InterceptorTest struct {
	TestService testpb.TestServiceServer
	ServerOpts  []grpc.ServerOption
	ClientOpts  []grpc.DialOption
	testing     *testing.T
	useTlS      bool

	serverAddr     string
	ServerListener net.Listener
	Server         *grpc.Server
	clientConn     *grpc.ClientConn
	Client         testpb.TestServiceClient

	restartServerWithDelayedStart chan time.Duration
	serverRunning                 chan bool
}

func NewTestInterceptor(t *testing.T, opts ...InterceptOption) (*InterceptorTest, error) {
	if t == nil {
		return nil, errNilTesting
	}
	middleware := &InterceptorTest{
		testing: t,
	}
	for _, opt := range opts {
		if err := opt(middleware); err != nil {
			t.Fatalf("error interceptor options: %v", err)
		}
	}
	return middleware, nil
}

func (it *InterceptorTest) Run() {
	it.restartServerWithDelayedStart = make(chan time.Duration)
	it.serverRunning = make(chan bool)

	it.serverAddr = "127.0.0.1:0"
	var err error
	certPEM, keyPEM, err = generateCertAndKey([]string{"localhost", "example.com"})
	if err != nil {
		it.testing.Fatalf("unable to generate test certificate/key: " + err.Error())
	}
	go func() {
		for {
			var err error
			it.ServerListener, err = net.Listen("tcp", it.serverAddr)
			if err != nil {
				it.testing.Fatalf("unable to listen on address %s: %v", it.serverAddr, err)
			}
			it.serverAddr = it.ServerListener.Addr().String()

			if it.useTlS {
				cert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					it.testing.Fatalf("unable to load test TLS certificate: %v", err)
				}
				creds := credentials.NewServerTLSFromCert(&cert)
				it.ServerOpts = append(it.ServerOpts, grpc.Creds(creds))
			}
			// This is the point where we hook up the interceptor
			it.Server = grpc.NewServer(it.ServerOpts...)
			// Create a service of the instantiator hasn't provided one.
			if it.TestService == nil {
				it.TestService = &grpc_testing.TestPingService{T: it.testing}
			}
			testpb.RegisterTestServiceServer(it.Server, it.TestService)

			go func() {
				it.Server.Serve(it.ServerListener)
			}()
			if it.Client == nil {
				it.Client = it.NewClient(it.ClientOpts...)
			}

			it.serverRunning <- true

			d := <-it.restartServerWithDelayedStart
			it.Server.Stop()
			time.Sleep(d)
		}
	}()

	select {
	case <-it.serverRunning:
	case <-time.After(2 * time.Second):
		it.testing.Fatal("server failed to start before deadline")
	}
}

func (it *InterceptorTest) NewClient(dialOpts ...grpc.DialOption) testpb.TestServiceClient {
	newDialOpts := append(dialOpts, grpc.WithBlock())
	if it.useTlS {
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(certPEM) {
			it.testing.Fatal("failed to append certificate")
		}
		creds := credentials.NewTLS(&tls.Config{ServerName: "localhost", RootCAs: cp})
		newDialOpts = append(newDialOpts, grpc.WithTransportCredentials(creds))
	} else {
		newDialOpts = append(newDialOpts, grpc.WithInsecure())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, err := grpc.DialContext(ctx, it.serverAddr, newDialOpts...)
	assert.NilError(it.testing, err, "must not error on client Dial")
	return testpb.NewTestServiceClient(clientConn)
}

func (it *InterceptorTest) Close() {
	time.Sleep(10 * time.Millisecond)
	if it.ServerListener != nil {
		it.Server.GracefulStop()
		it.testing.Logf("stopped grpc.Server at: %v", it.ServerAddr())
		it.ServerListener.Close()
	}
	if it.clientConn != nil {
		it.clientConn.Close()
	}
}

func (it *InterceptorTest) ServerAddr() string {
	return it.serverAddr
}

func (it *InterceptorTest) SimpleCtx() context.Context {
	ctx, _ := context.WithTimeout(context.TODO(), 2*time.Second)
	return ctx
}

func (it *InterceptorTest) DeadlineCtx(deadline time.Time) context.Context {
	ctx, _ := context.WithDeadline(context.TODO(), deadline)
	return ctx
}

// generateCertAndKey copied from https://github.com/johanbrandhorst/certify/blob/master/issuers/vault/vault_suite_test.go#L255
// with minor modifications.
func generateCertAndKey(san []string) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "example.com",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              san,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}
	certOut := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})
	keyOut := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})
	return certOut, keyOut, nil
}
