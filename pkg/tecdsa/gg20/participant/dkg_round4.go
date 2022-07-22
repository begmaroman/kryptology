//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"fmt"

	"gitlab.com/chainfusion/kryptology/internal"
	"gitlab.com/chainfusion/kryptology/pkg/core/curves"
	"gitlab.com/chainfusion/kryptology/pkg/paillier"
	v1 "gitlab.com/chainfusion/kryptology/pkg/sharing/v1"
	"gitlab.com/chainfusion/kryptology/pkg/tecdsa/gg20/dealer"
)

// DkgResult is all the data generated from the DKG
type DkgResult struct {
	SecretKey       *paillier.SecretKey
	ShamirShare     *v1.ShamirShare
	EcdsaPublicKey  *curves.EcPoint
	PublicShares    []*curves.EcPoint
	ParticipantData map[uint32]*DkgParticipantData
}

type DkgParticipantData struct {
	PublicKey   *paillier.PublicKey
	ProofParams *dealer.ProofParams
}

// DkgRound4 computes dkg round 4 as shown in
// [spec] fig. 5: DistKeyGenRound4
func (dp *DkgParticipant) DkgRound4(inBcast map[uint32]*DkgRound3Bcast) (*DkgResult, []uint32, error) {
	var failedParticipantIds []uint32
	var failedParticipantErrors []error

	if len(inBcast) == 0 {
		return nil, failedParticipantIds, internal.ErrIncorrectCount
	}
	if dp.Round != 4 {
		return nil, failedParticipantIds, internal.ErrInvalidRound
	}
	// Make sure all participants sent a proof
	for id := range dp.State.OtherParticipantData {
		if id == dp.Id {
			continue
		}
		if _, ok := inBcast[id]; !ok {
			failedParticipantIds = append(failedParticipantIds, id)
			failedParticipantErrors = append(failedParticipantErrors, fmt.Errorf("missing proof for participant"))
			continue
		}
	}

	if len(failedParticipantIds) != 0 {
		return nil, failedParticipantIds, makeParticipantsError(failedParticipantIds, failedParticipantErrors)
	}

	verifyPsfParams := paillier.PsfVerifyParams{
		Curve: dp.Curve,
		Y:     dp.State.Y,
	}
	// 1. for j = [1,...,n]
	for id, p := range inBcast {
		// 2. if i == j, continue
		if dp.Id == id {
			continue
		}
		verifyPsfParams.PublicKey = dp.State.OtherParticipantData[id].PublicKey
		verifyPsfParams.Pi = id
		// 3. if VerifyPSF(\pi_j, pk_j.N, y, g, q, pj) = false, abort
		if err := p.PsfProof.Verify(&verifyPsfParams); err != nil {
			failedParticipantIds = append(failedParticipantIds, id)
			failedParticipantErrors = append(failedParticipantErrors, err)
			continue
		}
	}

	if len(failedParticipantIds) != 0 {
		return nil, failedParticipantIds, makeParticipantsError(failedParticipantIds, failedParticipantErrors)
	}

	// Return paillier public keys and proof params
	// from all participants
	participantData := make(map[uint32]*DkgParticipantData)
	for id, data := range dp.State.OtherParticipantData {
		participantData[id] = &DkgParticipantData{
			PublicKey:   data.PublicKey,
			ProofParams: data.ProofParams,
		}
	}

	participantData[dp.Id] = &DkgParticipantData{
		PublicKey: dp.State.Pk,
		ProofParams: &dealer.ProofParams{
			N:  dp.State.N,
			H1: dp.State.H1,
			H2: dp.State.H2,
		},
	}

	// Return all necessary information to complete signing
	// the proof params, paillier public keys, and public commitments
	// from other participants, the secret signing key share, and
	// the public verification key
	return &DkgResult{
		SecretKey:       dp.State.Sk,
		ShamirShare:     dp.State.ShamirShare,
		EcdsaPublicKey:  dp.State.Y,
		PublicShares:    dp.State.PublicShares,
		ParticipantData: participantData,
	}, failedParticipantIds, nil
}
