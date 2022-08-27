package main

import (
	testpb "github.com/grpc-ecosystem/go-grpc-middleware/testing/testproto"
	"google.golang.org/grpc"
)

type InterceptOption func(it *InterceptorTest) error

func InterceptOptsServerOptions(srvOpts []grpc.ServerOption) InterceptOption {
	return func(it *InterceptorTest) error {
		if srvOpts == nil {
			return errNilServerOpts
		}
		it.ServerOpts = srvOpts
		return nil
	}
}

func InterceptOptsClientOptions(cliOpts []grpc.DialOption) InterceptOption {
	return func(it *InterceptorTest) error {
		if cliOpts == nil {
			return errNilClientOpts
		}
		it.ClientOpts = cliOpts
		return nil
	}
}

func InterceptOptsTestServer(testServer testpb.TestServiceServer) InterceptOption {
	return func(it *InterceptorTest) error {
		if testServer == nil {
			return errNilTestServer
		}
		it.TestService = testServer
		return nil
	}
}

func InterceptOptsUseTLS(tls bool) InterceptOption {
	return func(it *InterceptorTest) error {
		it.useTlS = tls
		return nil
	}
}
