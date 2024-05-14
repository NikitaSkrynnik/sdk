// Copyright (c) 2020-2021 Doc.ai and/or its affiliates.
//
// Copyright (c) 2022-2023 Cisco and/or its affiliates.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authorize_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"

	"crypto/x509"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/networkservicemesh/sdk/pkg/networkservice/common/authorize"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
	"github.com/networkservicemesh/sdk/pkg/networkservice/utils/inject/injecterror"
	"github.com/networkservicemesh/sdk/pkg/tools/nanoid"
	"github.com/networkservicemesh/sdk/pkg/tools/opa"

	_ "net/http/pprof"
)

func generateCert(u *url.URL) []byte {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		URIs:         []*url.URL{u},
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey

	certBytes, _ := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	return certBytes
}

func withPeer(ctx context.Context, certBytes []byte) (context.Context, error) {
	x509cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	authInfo := &credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{x509cert},
		},
	}
	return peer.NewContext(ctx, &peer.Peer{AuthInfo: authInfo}), nil
}

func testPolicy() string {
	return `
package test
	
default valid = false

valid {
		input.path_segments[_].token = "allowed"
}
`
}

func requestWithToken(token string) *networkservice.NetworkServiceRequest {
	return &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{
			Path: &networkservice.Path{
				Index: 0,
				PathSegments: []*networkservice.PathSegment{
					{
						Token: token,
					},
				},
			},
		},
	}
}

func TestAuthorize_ShouldCorrectlyWorkWithHeal(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	r := &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{
			Path: &networkservice.Path{
				PathSegments: []*networkservice.PathSegment{
					{},
				},
			},
		},
	}

	// simulate heal request
	conn, err := authorize.NewServer().Request(context.Background(), r)
	require.NoError(t, err)

	// simulate timeout close
	_, err = authorize.NewServer().Close(context.Background(), conn)
	require.NoError(t, err)
}

func TestAuthzEndpoint(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	dir := filepath.Clean(path.Join(os.TempDir(), t.Name()))
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	err := os.MkdirAll(dir, os.ModePerm)
	require.Nil(t, err)

	policyPath := filepath.Clean(path.Join(dir, "policy.rego"))
	err = os.WriteFile(policyPath, []byte(testPolicy()), os.ModePerm)
	require.Nil(t, err)

	suits := []struct {
		name       string
		policyPath string
		request    *networkservice.NetworkServiceRequest
		response   *networkservice.Connection
		denied     bool
	}{
		{
			name:       "simple positive test",
			policyPath: policyPath,
			request:    requestWithToken("allowed"),
			denied:     false,
		},
		{
			name:       "simple negative test",
			policyPath: policyPath,
			request:    requestWithToken("not_allowed"),
			denied:     true,
		},
	}

	for i := range suits {
		s := suits[i]
		t.Run(s.name, func(t *testing.T) {
			srv := authorize.NewServer(authorize.WithPolicies(s.policyPath))
			checkResult := func(err error) {
				if !s.denied {
					require.Nil(t, err, "request expected to be not denied: ")
					return
				}
				require.NotNil(t, err, "request expected to be denied")
				s, ok := status.FromError(errors.Cause(err))
				require.True(t, ok, "error without error status code"+err.Error())
				require.Equal(t, s.Code(), codes.PermissionDenied, "wrong error status code")
			}

			ctx := peer.NewContext(context.Background(), &peer.Peer{})

			_, err := srv.Request(ctx, s.request)
			checkResult(err)

			_, err = srv.Close(ctx, s.request.GetConnection())
			checkResult(err)
		})
	}
}

func TestAuthorize_EmptySpiffeIDConnectionMapOnClose(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })

	conn := &networkservice.Connection{
		Id: "conn",
		Path: &networkservice.Path{
			Index: 1,
			PathSegments: []*networkservice.PathSegment{
				{Id: "id-1"},
				{Id: "id-2"},
			},
		},
	}

	server := authorize.NewServer(authorize.Any())
	certBytes := generateCert(&url.URL{Scheme: "spiffe", Host: "test.com", Path: "test"})

	ctx, err := withPeer(context.Background(), certBytes)
	require.NoError(t, err)

	_, err = server.Close(ctx, conn)
	require.NoError(t, err)
}

func Run(f func()) int64 {
	var then = new(runtime.MemStats)
	var now = new(runtime.MemStats)

	runtime.GC()
	runtime.ReadMemStats(then)

	f()

	runtime.GC()
	runtime.ReadMemStats(now)

	fmt.Printf("HeapInuse: %d\n", int64(now.HeapInuse-then.HeapInuse))
	fmt.Printf("HeapObjects: %d\n", int64(now.HeapObjects-then.HeapObjects))

	return int64(now.HeapObjects - then.HeapObjects)
}

func generateRandomPath() *networkservice.Path {
	path := &networkservice.Path{}

	for i := 0; i < 10; i++ {
		seg := &networkservice.PathSegment{}
		seg.Id = nanoid.GenerateStringWithoutError(10)
		seg.Name = nanoid.GenerateStringWithoutError(10)
		seg.Token = nanoid.GenerateStringWithoutError(10)
		seg.Expires = &timestamppb.Timestamp{Seconds: mathrand.Int63()}
		path.PathSegments = append(path.PathSegments, seg)
	}

	path.Index = 9
	return path
}

func TestAuthorizeMemoryLeak(t *testing.T) {
	chain := next.NewNetworkServiceServer(
		authorize.NewServer(),
		injecterror.NewServer(injecterror.WithError(errors.New("Error"))),
	)

	request := &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{
			Id: "id",
		},
	}

	testLeak := func() {
		certBytes := generateCert(&url.URL{Scheme: "spiffe", Host: "test.com", Path: "test"})
		ctx, err := withPeer(context.Background(), certBytes)
		if err != nil {
			fmt.Println(err.Error())
		}
		request.Connection.Path = generateRandomPath()
		chain.Request(ctx, request)
	}

	Run(func() {
		for i := 0; i < 100000; i++ {
			testLeak()
		}
	})

	fmt.Println(http.ListenAndServe("localhost:6080", nil))
}

func TestOPAMemoryLeak(t *testing.T) {
	request := &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{
			Id: "id",
			Path: &networkservice.Path{
				Index: 7,
				PathSegments: []*networkservice.PathSegment{
					{
						Name:  "client",
						Token: "token",
						Id:    "clientid",
					},
					{
						Name:  "nsmgr",
						Token: "token",
						Id:    "nsmgrid",
					},
					{
						Name:  "client",
						Token: "token",
						Id:    "clientid",
					},
					{
						Name:  "nsmgr",
						Token: "token",
						Id:    "nsmgrid",
					},
					{
						Name:  "client",
						Token: "token",
						Id:    "clientid",
					},
					{
						Name:  "nsmgr",
						Token: "token",
						Id:    "nsmgrid",
					},
					{
						Name:  "client",
						Token: "token",
						Id:    "clientid",
					},
					{
						Name:  "nsmgr",
						Token: "token",
						Id:    "nsmgrid",
					},
				},
			},
		},
	}

	testLeak := func() {
		opa.PreparedOpaInput(context.Background(), request)
	}

	Run(func() {
		for i := 0; i < 1000000; i++ {
			testLeak()
		}
	})

	fmt.Println(http.ListenAndServe("localhost:6080", nil))
}
