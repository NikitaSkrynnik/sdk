// Copyright (c) 2024 Cisco and/or its affiliates.
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

package vl3_test

import (
	"context"
	"testing"

	"github.com/networkservicemesh/sdk/pkg/networkservice/connectioncontext/ipcontext/vl3"
	"github.com/stretchr/testify/require"
)

func TestSubscribtions(t *testing.T) {
	counter := 0
	ipam := new(vl3.IPAM)
	unsub1 := ipam.Subscribe(func() {
		counter += 1
	})
	unsub2 := ipam.Subscribe(func() {
		counter += 2
	})

	ipam.Reset(context.Background(), "10.0.0.1/24", nil)
	require.Equal(t, counter, 3)

	unsub2()
	ipam.Reset(context.Background(), "10.0.0.1/24", nil)
	require.Equal(t, counter, 4)

	unsub1()
	ipam.Reset(context.Background(), "10.0.0.1/24", nil)
	require.Equal(t, counter, 4)
}
