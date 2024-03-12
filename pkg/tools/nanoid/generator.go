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

// Package nanoid is a tiny, unique string ID generator
package nanoid

import (
	"crypto/rand"
	"math"
	"math/bits"
)

const (
	// DefaultAlphabet is the default alphabet for the generator which can be used to generate kernel interface names
	DefaultAlphabet = "!\"#$&'()*+,-.012456789;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
)

type generatorOpts struct {
	alphabet string
}

// Option represents options for the string generator
type Option func(o *generatorOpts)

// WithAlphabet sets a custom alphabet for the  generator
func WithAlphabet(alphabet string) Option {
	return func(o *generatorOpts) {
		o.alphabet = alphabet
	}
}

func generateRandomBuffer(step int) ([]byte, error) {
	buffer := make([]byte, step)
	if _, err := rand.Read(buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

// RandomString generates a random string based on size.
func RandomString(size int, opt ...Option) (string, error) {
	opts := &generatorOpts{
		alphabet: DefaultAlphabet,
	}

	for _, o := range opt {
		o(opts)
	}

	mask := 2<<uint32(31-bits.LeadingZeros32(uint32(len(opts.alphabet)-1|1))) - 1
	step := int(math.Ceil(1.6 * float64(mask*size) / float64(len(opts.alphabet))))

	id := make([]byte, size)

	for {
		randomBuffer, err := generateRandomBuffer(step)
		if err != nil {
			return "", err
		}

		j := 0
		for i := 0; i < step; i++ {
			currentIndex := int(randomBuffer[i]) & mask

			if currentIndex < len(opts.alphabet) {
				id[j] = opts.alphabet[currentIndex]
				j++
				if j == size {
					return string(id), nil
				}
			}
		}
	}
}
