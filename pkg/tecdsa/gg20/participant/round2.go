//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package participant

import (
	"math/big"

	"gitlab.com/chainfusion/kryptology/pkg/core"
	"gitlab.com/chainfusion/kryptology/pkg/paillier"
	"gitlab.com/chainfusion/kryptology/pkg/tecdsa/gg20/proof"
)

// Round2P2PSend is all the values that need to be sent to each player
type Round2P2PSend struct {
	Proof2, Proof3 *proof.ResponseProof
}

// SignRound2 performs round 2 signing operations for a single signer
// Trusted Dealer Mode: see [spec] fig 7: SignRound2
// DKG Mode: see [spec] fig 8: SignRound2
func (signer *Signer) SignRound2(inBcast map[uint32]*Round1Bcast, inP2P map[uint32]*Round1P2PSend) (map[uint32]*Round2P2PSend, []uint32, error) {
	var failedCosignerIds []uint32
	var failedCosignerErrors []error

	if err := signer.verifyStateMap(2, inBcast); err != nil {
		return nil, nil, err
	}
	// In dearlerless version, p2p map must contain one message from each cosigner.
	if !signer.state.keyGenType.IsTrustedDealer() {
		if err := signer.verifyStateMap(2, inP2P); err != nil {
			return nil, nil, err
		}
	}

	cnt := signer.Threshold - 1
	p2PSend := make(map[uint32]*Round2P2PSend, cnt)
	signer.state.betaj = make(map[uint32]*big.Int, cnt)
	signer.state.vuj = make(map[uint32]*big.Int, cnt)
	signer.state.cj = make(map[uint32]paillier.Ciphertext, cnt)
	signer.state.Cj = make(map[uint32]core.Commitment, cnt)

	// This is outside the loop for efficiency since the only changing value is the
	// params ciphertext
	pp := &proof.Proof1Params{
		Curve:        signer.Curve,
		DealerParams: signer.state.keyGenType.GetProofParams(signer.Id),
	}
	rpp := proof.ResponseProofParams{
		Curve: signer.Curve,
		B:     signer.PublicSharesMap[signer.Id].Point,
	}

	// 1. For j = [1 ... t+1]
	for j, param := range inBcast {
		// 2. if i == j, continue
		if param == nil || j == signer.Id {
			continue
		}

		// 3. if MtAVerifyRange(\pi_j^{Range1}, g, q, N~, h1, h2, c_j) == False then Abort
		pp.Pk = signer.state.pks[j]
		pp.C = param.Ctxt

		if signer.state.keyGenType.IsTrustedDealer() {
			if err := param.Proof.Verify(pp); err != nil {
				failedCosignerIds = append(failedCosignerIds, j)
				failedCosignerErrors = append(failedCosignerErrors, err)
				continue
			}
		} else {
			// The case using DKG, verify range proof in P2PSend
			if err := inP2P[j].Range1Proof.Verify(pp); err != nil {
				failedCosignerIds = append(failedCosignerIds, j)
				failedCosignerErrors = append(failedCosignerErrors, err)
				continue
			}
		}

		// 4. Compute c^{\gamma}_{ji}, \beta_{ji}, \pi^{Range2}_{ji} = MtaResponse(γ_i,g,q,pk_j,N~,h1,h2,c_j)
		rpp.C1 = param.Ctxt
		rpp.DealerParams = signer.state.keyGenType.GetProofParams(j)
		rpp.SmallB = signer.state.gammai
		rpp.Pk = signer.state.pks[j]
		proofGamma, err := rpp.Prove()
		if err != nil {
			failedCosignerIds = append(failedCosignerIds, j)
			failedCosignerErrors = append(failedCosignerErrors, err)
			continue
		}

		// 5. Compute c^{w}_{ji}, \vu_{ji}, \pi^{Range3}_{ji} = MtaResponse_wc(w_i,W_i,g,q,pk_j,N~,h1,h2,c_j)
		rpp.SmallB = signer.ShamirShare.Value.BigInt()
		proofW, err := rpp.ProveWc()
		if err != nil {
			failedCosignerIds = append(failedCosignerIds, j)
			failedCosignerErrors = append(failedCosignerErrors, err)
			continue
		}

		// Store the values for later rounds
		signer.state.cj[j] = param.Ctxt
		signer.state.betaj[j] = proofGamma.Beta
		signer.state.vuj[j] = proofW.Beta
		signer.state.Cj[j] = param.C

		// Beta and vu are not sent to other signers
		proofGamma.Beta = nil
		proofW.Beta = nil

		// 6. P2PSend(c^{gamma}_{ji}, c_^{W}_{ji}, \pi^{Range2}_{ji}, \pi^{Range3}_{ji})
		p2PSend[j] = &Round2P2PSend{
			Proof2: proofGamma,
			Proof3: proofW,
		}
	}

	if len(failedCosignerIds) != 0 {
		return nil, failedCosignerIds, makeCosignerError(failedCosignerIds, failedCosignerErrors)
	}

	signer.Round = 3
	return p2PSend, nil, nil
}
