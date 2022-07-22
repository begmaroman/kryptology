//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"crypto/elliptic"
	"fmt"
	"math/big"

	"gitlab.com/chainfusion/kryptology/internal"
	"gitlab.com/chainfusion/kryptology/pkg/core"
	"gitlab.com/chainfusion/kryptology/pkg/core/curves"
	"gitlab.com/chainfusion/kryptology/pkg/paillier"
	v1 "gitlab.com/chainfusion/kryptology/pkg/sharing/v1"
)

type DkgRound3Bcast struct {
	PsfProof paillier.PsfProof
}

// DkgRound3 computes dkg round 3 as shown in
// [spec] fig. 5: DistKeyGenRoun3
func (dp *DkgParticipant) DkgRound3(inBcast map[uint32]*DkgRound2Bcast, inP2P map[uint32]*DkgRound2P2PSend) (*DkgRound3Bcast, []uint32, error) {
	var failedParticipantIds []uint32
	var failedParticipantErrors []error

	if len(inBcast) == 0 || len(inP2P) == 0 {
		return nil, failedParticipantIds, internal.ErrNilArguments
	}
	if dp.Round != 3 {
		return nil, failedParticipantIds, internal.ErrInvalidRound
	}

	// Extract the share verifiers from the commitment
	verifiers := make(map[uint32][]*v1.ShareVerifier, len(inBcast))
	// NOTE: ID-1 because participant IDs are 1-based
	verifiers[dp.Id] = dp.State.V
	verifierSize := internal.CalcFieldSize(dp.Curve) * 2
	feldman, err := v1.NewFeldman(dp.State.Threshold, dp.State.Limit, dp.Curve)
	if err != nil {
		return nil, failedParticipantIds, err
	}

	// 1. set xi = xii
	xi := dp.State.X[dp.Id-1]

	// 2. for j = [1,...,n]
	for j, wit := range inBcast {
		// 3. if i == j continue
		if j == dp.Id {
			continue
		}

		// 4. Compute [vj0, . . . , vjt] ←Open(Cj , Dj )
		if ok, err := core.Open(dp.State.OtherParticipantData[j].Commitment, *wit.Di); !ok {
			if err != nil {
				failedParticipantIds = append(failedParticipantIds, j)
				failedParticipantErrors = append(failedParticipantErrors, err)
				continue
			} else {
				failedParticipantIds = append(failedParticipantIds, j)
				failedParticipantErrors = append(failedParticipantErrors, fmt.Errorf("invalid witness for participant"))
				continue
			}
		}

		verifiers[j], err = unmarshalFeldmanVerifiers(dp.Curve, wit.Di.Msg, verifierSize, int(dp.State.Threshold))
		if err != nil {
			failedParticipantIds = append(failedParticipantIds, j)
			failedParticipantErrors = append(failedParticipantErrors, err)
			continue
		}

		// 6. If FeldmanVerify(g, q, xji, pi, [vj0, . . . , vjt]) = False, Abort
		if ok, err := feldman.Verify(inP2P[j].Xij, verifiers[j]); !ok {
			if err != nil {
				failedParticipantIds = append(failedParticipantIds, j)
				failedParticipantErrors = append(failedParticipantErrors, err)
				continue
			} else {
				failedParticipantIds = append(failedParticipantIds, j)
				failedParticipantErrors = append(failedParticipantErrors, fmt.Errorf("invalid share for participant"))
				continue
			}
		}

		// 7. Compute xi = xi + xji mod q
		xi.Value = xi.Value.Add(inP2P[j].Xij.Value)
	}

	if len(failedParticipantIds) != 0 {
		return nil, failedParticipantIds, makeParticipantsError(failedParticipantIds, failedParticipantErrors)
	}

	v := make([]*curves.EcPoint, dp.State.Threshold)
	// 8. for j = [0,...,t]
	for j := 0; j < int(dp.State.Threshold); j++ {
		// 9. Set vj = 1 or identity point
		v[j], err = curves.NewScalarBaseMult(dp.Curve, big.NewInt(0))
		if err != nil {
			failedParticipantIds = append(failedParticipantIds, uint32(j+1))
			failedParticipantErrors = append(failedParticipantErrors, err)
			continue
		}

		// 10. for k = [1,...,n]
		for _, verifier := range verifiers {
			// 11. Compute vj = vj · vkj in G
			v[j], err = v[j].Add(verifier[j])
			if err != nil {
				failedParticipantIds = append(failedParticipantIds, uint32(j+1))
				failedParticipantErrors = append(failedParticipantErrors, err)
				continue
			}
		}
	}

	if len(failedParticipantIds) != 0 {
		return nil, failedParticipantIds, makeParticipantsError(failedParticipantIds, failedParticipantErrors)
	}

	// 12. y = v0 i.e the public key
	y := v[0]

	// This is a sanity check to make sure nothing went wrong when
	// computing the public key
	if !dp.Curve.IsOnCurve(y.X, y.Y) || y.IsIdentity() {
		return nil, failedParticipantIds, fmt.Errorf("invalid public key")
	}

	// Xj's
	publicShares := make([]*curves.EcPoint, dp.State.Limit)

	// 13. for j = [1,...,n]
	for j := 0; j < int(dp.State.Limit); j++ {
		id := uint32(j + 1)
		// 14. Set Xj = y
		publicShares[j] = &curves.EcPoint{
			Curve: dp.Curve,
			X:     new(big.Int).Set(y.X),
			Y:     new(big.Int).Set(y.Y),
		}
		// 15. for k = [1,...,t]
		for k := 0; k < int(dp.State.Threshold); k++ {
			// 16. compute ck = pj^k mod q
			pj := big.NewInt(int64(id))
			ck, err := core.Mul(pj, big.NewInt(int64(k+1)), dp.Curve.Params().N)
			if err != nil {
				failedParticipantIds = append(failedParticipantIds, id)
				failedParticipantErrors = append(failedParticipantErrors, err)
				continue
			}
			// 17. compute Xj = Xj x vk ^ ck in G
			t, err := v[k].ScalarMult(ck)
			if err != nil {
				failedParticipantIds = append(failedParticipantIds, id)
				failedParticipantErrors = append(failedParticipantErrors, err)
				continue
			}
			// Xj = Xj * t in G
			publicShares[j], err = publicShares[j].Add(t)
			if err != nil {
				failedParticipantIds = append(failedParticipantIds, id)
				failedParticipantErrors = append(failedParticipantErrors, err)
				continue
			}
		}
	}

	if len(failedParticipantIds) != 0 {
		return nil, failedParticipantIds, makeParticipantsError(failedParticipantIds, failedParticipantErrors)
	}

	// 18. Compute πPSF = ProvePSF(ski.N, ski.φ(N), y, g, q, pi)
	psfParams := paillier.PsfProofParams{
		Curve:     dp.Curve,
		SecretKey: dp.State.Sk,
		Pi:        dp.Id,
		Y:         y,
	}
	psfProof, err := psfParams.Prove()
	if err != nil {
		return nil, failedParticipantIds, err
	}

	dp.Round = 4
	dp.State.Y = y
	dp.State.ShamirShare = xi
	dp.State.PublicShares = publicShares

	return &DkgRound3Bcast{psfProof}, failedParticipantIds, nil
}

// unmarshalFeldmanVerifiers converts a byte sequence into
// a number of feldman verifiers
func unmarshalFeldmanVerifiers(curve elliptic.Curve, msg []byte, verifierSize, threshold int) ([]*v1.ShareVerifier, error) {
	if len(msg)%verifierSize != 0 {
		return nil, fmt.Errorf("invalid committed verifier shares")
	}
	numShares := len(msg) / verifierSize

	// 5. If [vj0,...,vjt] = ⊥, Abort
	if numShares != threshold {
		return nil, fmt.Errorf("invalid number of verifier shares")
	}

	// Extract verifiers from bytes
	verifiers := make([]*v1.ShareVerifier, numShares)
	var err error
	for k := 0; k < numShares; k++ {
		value := make([]byte, verifierSize)
		copy(value, msg[k*verifierSize:(k+1)*verifierSize])
		verifiers[k], err = curves.PointFromBytesUncompressed(curve, value)
		if err != nil {
			return nil, err
		}
	}

	return verifiers, nil
}
