// Copyright (c) 2021-2022 Cisco and/or its affiliates.
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

package dial

import (
	"context"
	"net/url"
	"runtime"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/networkservicemesh/sdk/pkg/tools/clock"
	"github.com/networkservicemesh/sdk/pkg/tools/grpcutils"
	"github.com/networkservicemesh/sdk/pkg/tools/log"
)

type dialer struct {
	ctx            context.Context
	cleanupContext context.Context
	clientURL      *url.URL
	done           chan struct{}
	*grpc.ClientConn
	dialOptions []grpc.DialOption
	dialTimeout time.Duration
}

func newDialer(ctx context.Context, dialTimeout time.Duration, dialOptions ...grpc.DialOption) *dialer {
	return &dialer{
		ctx:         ctx,
		dialOptions: dialOptions,
		dialTimeout: dialTimeout,
	}
}

func (di *dialer) Dial(ctx context.Context, clientURL *url.URL) error {
	log.FromContext(ctx).WithField("time", time.Now()).Infof("dialer 0")

	if di == nil {
		return errors.New("cannot call dialer.Dial on  nil dialer")
	}
	// Cleanup any previous grpc.ClientConn
	if di.done != nil {
		close(di.done)
		di.done = nil
	}

	// Set the clientURL
	di.clientURL = clientURL

	// Setup dialTimeout if needed
	dialCtx := ctx
	if di.dialTimeout != 0 {
		dialCtx, _ = clock.FromContext(di.ctx).WithTimeout(dialCtx, di.dialTimeout)
	}

	log.FromContext(ctx).WithField("time", time.Now()).Infof("dialer 1")
	// Dial
	//////// 600ms
	target := grpcutils.URLToTarget(di.clientURL)
	cc, err := grpc.DialContext(dialCtx, target, di.dialOptions...)
	if err != nil {
		if cc != nil {
			_ = cc.Close()
		}
		return errors.Wrapf(err, "failed to dial %s", target)
	}
	di.ClientConn = cc
	////////

	log.FromContext(ctx).WithField("time", time.Now()).Infof("dialer 2")

	/////// 150 ms?

	go func(done <-chan struct{}, cc *grpc.ClientConn) {
		<-done
		_ = cc.Close()
	}(di.done, cc)
	///////

	log.FromContext(ctx).WithField("time", time.Now()).Infof("dialer 3")
	return nil
}

func (di *dialer) Close() error {
	if di != nil && di.done != nil {
		close(di.done)
		di.done = nil
		runtime.Gosched()
	}
	return nil
}

func (di *dialer) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	if di.ClientConn == nil {
		return errors.New("no dialer.ClientConn found")
	}
	return di.ClientConn.Invoke(ctx, method, args, reply, opts...)
}

func (di *dialer) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	if di.ClientConn == nil {
		return nil, errors.New("no dialer.ClientConn found")
	}
	return di.ClientConn.NewStream(ctx, desc, method, opts...)
}
