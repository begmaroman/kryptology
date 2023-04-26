//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"

	"github.com/nerifnetwork/kryptology/internal"
	"github.com/nerifnetwork/kryptology/pkg/core"
	"github.com/nerifnetwork/kryptology/pkg/paillier"
	v1 "github.com/nerifnetwork/kryptology/pkg/sharing/v1"
	"github.com/nerifnetwork/kryptology/pkg/tecdsa/gg20/dealer"
	"github.com/nerifnetwork/kryptology/pkg/tecdsa/gg20/proof"
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
func (dp *DkgParticipant) DkgRound2(inBcast map[uint32]*DkgRound1Bcast) (*DkgRound2Bcast, map[uint32]*DkgRound2P2PSend, []uint32, error) {
	var failedParticipantIds []uint32
	var failedParticipantErrors []error
	// Make sure dkg participant is not empty
	if dp == nil || dp.Curve == nil {
		return nil, nil, failedParticipantIds, internal.ErrNilArguments
	}

	// Check DkgParticipant has the correct dkg round number
	if err := dp.verifyDkgRound(2); err != nil {
		return nil, nil, failedParticipantIds, err
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
		return nil, nil, failedParticipantIds, internal.ErrIncorrectCount
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
			failedParticipantIds = append(failedParticipantIds, id)
			failedParticipantErrors = append(failedParticipantErrors, fmt.Errorf("invalid paillier keys"))
			continue
		}

		// If VerifyCompositeDL(pi_1j^CDL, g, q, h1j, h2j, tildeN_j) = False, Abort
		cdlParams1.H1 = param.H1i
		cdlParams1.H2 = param.H2i
		cdlParams1.N = param.Ni
		if err := param.Proof1i.Verify(&cdlParams1); err != nil {
			failedParticipantIds = append(failedParticipantIds, id)
			failedParticipantErrors = append(failedParticipantErrors, err)
			continue
		}

		// If VerifyCompositeDL(pi_2j^CDL, g, q, h2j, h1j, tildeN_j) = False, Abort
		// Note the position of h1j and h2j, they are reversed in the second verification!
		cdlParams2.H1 = param.H2i
		cdlParams2.H2 = param.H1i
		cdlParams2.N = param.Ni
		if err := param.Proof2i.Verify(&cdlParams2); err != nil {
			failedParticipantIds = append(failedParticipantIds, id)
			failedParticipantErrors = append(failedParticipantErrors, err)
			continue
		}

		// P2PSend xij to player Pj
		if dp.State.X == nil || dp.State.X[id-1] == nil {
			failedParticipantIds = append(failedParticipantIds, id)
			failedParticipantErrors = append(failedParticipantErrors, fmt.Errorf("missing Shamir share to P2P send"))
			continue
		}
		p2PSend[id] = &DkgRound2P2PSend{
			Xij: dp.State.X[id-1],
		}

		// Store other parties data
		//TODO: validate Identifier and Ci
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

	if len(failedParticipantIds) != 0 {
		return nil, nil, failedParticipantIds, makeParticipantsError(failedParticipantIds, failedParticipantErrors)
	}

	// Assign dkg round to 3
	dp.Round = 3

	// EchoBroadcast Di to all other players. Also return it with P2PSend
	return &DkgRound2Bcast{
		Di: dp.State.D,
	}, p2PSend, failedParticipantIds, nil
}
