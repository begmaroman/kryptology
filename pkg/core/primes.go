//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package core

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
)

// GenerateSafePrime creates a prime number `p`
// where (`p`-1)/2 is also prime with at least `bits`
func GenerateSafePrime(bits uint) (*big.Int, error) {
	if bits < 3 {
		return nil, fmt.Errorf("safe prime size must be at least 3-bits")
	}

	var p *big.Int
	var err error
	checks := int(math.Max(float64(bits)/16, 8))
	for {
		// rand.Prime throws an error if bits < 2
		// -1 so the Sophie-Germain prime is 1023 bits
		// and the Safe prime is 1024
		p, err = rand.Prime(rand.Reader, int(bits)-1)
		if err != nil {
			return nil, err
		}
		p.Add(p.Lsh(p, 1), One)

		if p.ProbablyPrime(checks) {
			break
		}
	}

	return p, nil
}

// GenerateSafePrimeParallel is a parallelized version of GenerateSafePrime
func GenerateSafePrimeParallel(bits uint, n int) (*big.Int, error) {
	if bits < 3 {
		return nil, fmt.Errorf("safe prime size must be at least 3-bits")
	}

	done := make(chan struct{})
	results := make(chan *big.Int)

	generator := func(results chan<- *big.Int) {
		for {
			select {
			case <-done:
				return
			default:
			}

			// rand.Prime throws an error if bits < 2
			// -1 so the Sophie-Germain prime is 1023 bits
			// and the Safe prime is 1024
			p, err := rand.Prime(rand.Reader, int(bits)-1)
			if err != nil {
				panic(err)
			}

			p.Add(p.Lsh(p, 1), One)

			results <- p
		}
	}

	for i := 0; i < n; i++ {
		go generator(results)
	}

	var p *big.Int
	checks := int(math.Max(float64(bits)/16, 8))
	for {
		p = <-results

		if p.ProbablyPrime(checks) {
			close(done)
			break
		}
	}

	return p, nil
}
