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
	"google.golang.org/grpc"

	"github.com/networkservicemesh/api/pkg/api/networkservice"

	"github.com/networkservicemesh/sdk/pkg/networkservice/core/next"
)

type beginTraceClient struct {
	traced networkservice.NetworkServiceClient
}

type endTraceClient struct{}

// NewNetworkServiceClient - wraps tracing around the supplied networkservice.NetworkServiceClient
func NewNetworkServiceClient(traced networkservice.NetworkServiceClient) networkservice.NetworkServiceClient {
	return next.NewNetworkServiceClient(
		&beginTraceClient{traced: traced},
		&endTraceClient{},
	)
}

func (t *beginTraceClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	rv, err := t.traced.Request(ctx, request, opts...)
	if err != nil {
		return nil, err
	}
	return rv, err
}

func (t *beginTraceClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	rv, err := t.traced.Close(ctx, conn, opts...)
	if err != nil {
		return nil, err
	}

	return rv, err
}

func (t *endTraceClient) Request(ctx context.Context, request *networkservice.NetworkServiceRequest, opts ...grpc.CallOption) (*networkservice.Connection, error) {
	conn, err := next.Client(ctx).Request(ctx, request, opts...)
	return conn, err
}

func (t *endTraceClient) Close(ctx context.Context, conn *networkservice.Connection, opts ...grpc.CallOption) (*empty.Empty, error) {
	r, err := next.Client(ctx).Close(ctx, conn, opts...)
	return r, err
}
