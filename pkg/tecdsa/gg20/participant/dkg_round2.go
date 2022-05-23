//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"

	"gitlab.com/chainfusion/kryptology/internal"
	"gitlab.com/chainfusion/kryptology/pkg/core"
	"gitlab.com/chainfusion/kryptology/pkg/paillier"
	v1 "gitlab.com/chainfusion/kryptology/pkg/sharing/v1"
	"gitlab.com/chainfusion/kryptology/pkg/tecdsa/gg20/dealer"
	"gitlab.com/chainfusion/kryptology/pkg/tecdsa/gg20/proof"
)

// DkgRound2Bcast contains value that will be echo broadcast to all other players.
type DkgRound2Bcast struct {
	Di *core.Witness
}

// DkgRound2P2PSend contains value that will be P2PSend to all other player Pj
type DkgRound2P2PSend struct {
	Xij *v1.ShamirShare
}

// DkgRound2 implements distributed key generation round 2
// [spec] fig 5: DistKeyGenRound2
func (dp *DkgParticipant) DkgRound2(inBcast map[uint32]*DkgRound1Bcast) (*DkgRound2Bcast, map[uint32]*DkgRound2P2PSend, error) {
	// Make sure dkg participant is not empty
	if dp == nil || dp.Curve == nil {
		return nil, nil, internal.ErrNilArguments
	}

	// Check DkgParticipant has the correct dkg round number
	if err := dp.verifyDkgRound(2); err != nil {
		return nil, nil, err
	}

	// Check the total number of parties
	cnt := 0
	for id := range inBcast {
		if inBcast[id] == nil {
			continue
		}
		if id == dp.Id {
			continue
		}
		cnt++
	}
	if uint32(cnt) != dp.State.Limit-1 {
		return nil, nil, internal.ErrIncorrectCount
	}

	// Initiate P2P channel to other parties
	p2PSend := make(map[uint32]*DkgRound2P2PSend)

	// Initiate two CdlVerifyParams that will be used in CDL verification.
	cdlParams1 := proof.CdlVerifyParams{
		Curve: dp.Curve,
	}
	cdlParams2 := proof.CdlVerifyParams{
		Curve: dp.Curve,
	}

	dp.State.OtherParticipantData = make(map[uint32]*DkgParticipantCommitment)

	// For j = [1...n]
	expKeySize := 2 * paillier.PaillierPrimeBits
	for id, param := range inBcast {
		// If i = j, Continue
		if id == dp.Id {
			continue
		}

		// Mitigate possible attack from
		// https://eprint.iacr.org/2021/1621.pdf
		// by checking that paillier keys are the correct size
		// See section 5
		bitlen := param.Pki.N.BitLen()
		if bitlen != expKeySize &&
			bitlen != expKeySize-1 {
			return nil, nil, fmt.Errorf("invalid paillier keys")
		}

		// If VerifyCompositeDL(pi_1j^CDL, g, q, h1j, h2j, tildeN_j) = False, Abort
		cdlParams1.H1 = param.H1i
		cdlParams1.H2 = param.H2i
		cdlParams1.N = param.Ni
		if err := param.Proof1i.Verify(&cdlParams1); err != nil {
			return nil, nil, err
		}

		// If VerifyCompositeDL(pi_2j^CDL, g, q, h2j, h1j, tildeN_j) = False, Abort
		// Note the position of h1j and h2j, they are reversed in the second verification!
		cdlParams2.H1 = param.H2i
		cdlParams2.H2 = param.H1i
		cdlParams2.N = param.Ni
		if err := param.Proof2i.Verify(&cdlParams2); err != nil {
			return nil, nil, err
		}

		// P2PSend xij to player Pj
		if dp.State.X == nil || dp.State.X[id-1] == nil {
			return nil, nil, fmt.Errorf("missing Shamir share to P2P send")
		}
		p2PSend[id] = &DkgRound2P2PSend{
			Xij: dp.State.X[id-1],
		}

		// Store other parties data
		dp.State.OtherParticipantData[id] = &DkgParticipantCommitment{
			PublicKey:  param.Pki,
			Commitment: param.Ci,
			ProofParams: &dealer.ProofParams{
				N:  param.Ni,
				H1: param.H1i,
				H2: param.H2i,
			},
		}
	}

	// Assign dkg round to 3
	dp.Round = 3

	// EchoBroadcast Di to all other players. Also return it with P2PSend
	return &DkgRound2Bcast{
		Di: dp.State.D,
	}, p2PSend, nil
}
