// Copyright (c) 2020-2023 Cisco Systems, Inc.
//
// Copyright (c) 2021-2023 Doc.ai and/or its affiliates.
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

package traceverbose

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type beginTraceServer struct {
	traced networkservice.NetworkServiceServer
}

type endTraceServer struct{}

// NewNetworkServiceServer - wraps tracing around the supplied traced
func NewNetworkServiceServer(traced networkservice.NetworkServiceServer) networkservice.NetworkServiceServer {
	return next.NewNetworkServiceServer(
		&beginTraceServer{traced: traced},
		&endTraceServer{},
	)
}

func (t *beginTraceServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	rv, err := t.traced.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	return rv, err
}

func (t *beginTraceServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	rv, err := t.traced.Close(ctx, conn)
	if err != nil {
		return nil, err
	}
	return rv, err
}

func (t *endTraceServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	conn, err := next.Server(ctx).Request(ctx, request)
	return conn, err
}

func (t *endTraceServer) Close(ctx context.Context, conn *networkservice.Connection) (*empty.Empty, error) {
	r, err := next.Server(ctx).Close(ctx, conn)
	return r, err
}
