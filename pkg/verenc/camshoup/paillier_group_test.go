//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package camshoup

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"gitlab.com/chainfusion/kryptology/internal"
	crypto "gitlab.com/chainfusion/kryptology/pkg/core"
)

var (
	// taken from https://github.com/mikelodder7/cunningham_chain/blob/master/findings.md
	testP = internal.B10("37313426856874901938110133384605074194791927500210707276948918975046371522830901596065044944558427864187196889881993164303255749681644627614963632713725183364319410825898054225147061624559894980555489070322738683900143562848200257354774040241218537613789091499134051387344396560066242901217378861764936185029")
	testQ = internal.B10("89884656743115795386465259539451236680898848947115328636715040578866337902750481566354238661203768010560056939935696678829394884407208311246423715319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417678164815053566739")
)

func TestPaillierGroupAbs(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	var tests = []struct {
		tst, expt *big.Int
	}{
		{new(big.Int).Sub(group.n2, big.NewInt(1)), big.NewInt(1)},
		{new(big.Int).Add(group.n2, big.NewInt(1)), big.NewInt(1)},
		{new(big.Int).Sub(group.n2d2, big.NewInt(1)), new(big.Int).Sub(group.n2d2, big.NewInt(1))},
		{new(big.Int).Sub(group.n2d2, big.NewInt(2)), new(big.Int).Sub(group.n2d2, big.NewInt(2))},
	}

	// fixed tests
	for _, test := range tests {
		require.Equal(t, test.expt, group.Abs(test.tst))
	}

	// random tests
	for i := 0; i < 10; i++ {
		v, err := group.Rand()
		require.NoError(t, err)
		absV := group.Abs(v)
		vSqr, err := crypto.Mul(v, v, group.n2)
		require.NoError(t, err)
		absVSqr, err := crypto.Mul(absV, absV, group.n2)
		require.NoError(t, err)
		// v^2 == abs(v)^2
		require.Equal(t, vSqr, absVSqr)
	}
}

func TestPaillierGroupGexp(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	group.g = big.NewInt(3)
	tests := []struct {
		tst, expt *big.Int
	}{
		{big.NewInt(2), big.NewInt(9)},
		{big.NewInt(3), big.NewInt(27)},
		{big.NewInt(-1), internal.B10("7499117220481606893649407997399583308623268248762862128736872698824860600842539649858603415089499373731123393918622048306032453674117198222428763400911316711446714484238108131853998795190806064022005540191591261850583540110613493142117711175554687907993186406437781941775859626227440416706732352534320731439315078729078870773717897878277521899968765343474198143801766637939617094139165566543814621094727209827280235001003967993120858315015118799915363205353758729304376784293822322166655094010593701655935398294477352938710477213434893715051831645405694928356029906438589615124561537156384355180319348277134506296769629916781958368753909584086440228342500729108626734803375134884502083805712504675865246881229463006603396559380854179010152629093144420272779479646825835945201621434552737270891411188707165574852172520548208219404678615150837351570584275400292453510652907722111673821881050068428228292352163743877772993566777118954034996545482953390011456036779111442131310187063702793015171803441885940720487623309201563428243215588648533078389653349518182776849735665081821416965810759310263601486813425303956567680549257436019232011620365483794625689049981027436030969508646999754826253132633834825366188937693881675421518323841")},
	}
	// fixed tests
	for _, test := range tests {
		require.Equal(t, test.expt, group.Gexp(test.tst))
	}
}

func TestPaillierGroupInv(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	tests := []struct {
		tst, expt *big.Int
	}{
		{big.NewInt(3), internal.B10("7499117220481606893649407997399583308623268248762862128736872698824860600842539649858603415089499373731123393918622048306032453674117198222428763400911316711446714484238108131853998795190806064022005540191591261850583540110613493142117711175554687907993186406437781941775859626227440416706732352534320731439315078729078870773717897878277521899968765343474198143801766637939617094139165566543814621094727209827280235001003967993120858315015118799915363205353758729304376784293822322166655094010593701655935398294477352938710477213434893715051831645405694928356029906438589615124561537156384355180319348277134506296769629916781958368753909584086440228342500729108626734803375134884502083805712504675865246881229463006603396559380854179010152629093144420272779479646825835945201621434552737270891411188707165574852172520548208219404678615150837351570584275400292453510652907722111673821881050068428228292352163743877772993566777118954034996545482953390011456036779111442131310187063702793015171803441885940720487623309201563428243215588648533078389653349518182776849735665081821416965810759310263601486813425303956567680549257436019232011620365483794625689049981027436030969508646999754826253132633834825366188937693881675421518323841")},
		{big.NewInt(2), internal.B10("5624337915361205170237055998049687481467451186572146596552654524118645450631904737393952561317124530298342545438966536229524340255587898666821572550683487533585035863178581098890499096393104548016504155143693446387937655082960119856588283381666015930994889804828336456331894719670580312530049264400740548579486309046809153080288423408708141424976574007605648607851324978454712820604374174907860965821045407370460176250752975994840643736261339099936522404015319046978282588220366741624991320507945276241951548720858014704032857910076170286288873734054271196267022429828942211343421152867288266385239511207850879722577222437586468776565432188064830171256875546831470051102531351163376562854284378506898935160922097254952547419535640634257614471819858315204584609735119376958901216075914552953168558391530374181139129390411156164553508961363128013677938206550219340132989680791583755366410787551321171219264122807908329745175082839215526247409112215042508592027584333581598482640297777094761378852581414455540365717481901172571182411691486399808792240012138637082637301748811366062724358069482697701115110068977967425760411943077014424008715274112845969266787485770577023227131485249816119689849475376119024641703270411256566138742881")},
		{big.NewInt(1), big.NewInt(1)},
	}
	for _, test := range tests {
		tv := group.Inv(test.tst)
		require.Equal(t, test.expt, tv)
		tv1 := group.Inv(tv)
		require.Equal(t, tv1, test.tst)
	}
}

func TestPaillierGroupHexp(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	group.h = big.NewInt(3)
	tests := []struct {
		tst, expt *big.Int
	}{
		{big.NewInt(2), big.NewInt(9)},
		{big.NewInt(3), big.NewInt(27)},
		{big.NewInt(-1), internal.B10("7499117220481606893649407997399583308623268248762862128736872698824860600842539649858603415089499373731123393918622048306032453674117198222428763400911316711446714484238108131853998795190806064022005540191591261850583540110613493142117711175554687907993186406437781941775859626227440416706732352534320731439315078729078870773717897878277521899968765343474198143801766637939617094139165566543814621094727209827280235001003967993120858315015118799915363205353758729304376784293822322166655094010593701655935398294477352938710477213434893715051831645405694928356029906438589615124561537156384355180319348277134506296769629916781958368753909584086440228342500729108626734803375134884502083805712504675865246881229463006603396559380854179010152629093144420272779479646825835945201621434552737270891411188707165574852172520548208219404678615150837351570584275400292453510652907722111673821881050068428228292352163743877772993566777118954034996545482953390011456036779111442131310187063702793015171803441885940720487623309201563428243215588648533078389653349518182776849735665081821416965810759310263601486813425303956567680549257436019232011620365483794625689049981027436030969508646999754826253132633834825366188937693881675421518323841")},
	}
	// fixed tests
	for _, test := range tests {
		require.Equal(t, test.expt, group.Hexp(test.tst))
	}
}

func TestPaillierGroupRand(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	for i := 0; i < 20; i++ {
		v, err := group.Rand()
		require.NoError(t, err)
		require.Equal(t, v.Cmp(group.n2d4), -1)
		require.Equal(t, v.Cmp(big.NewInt(0)), 1)
	}
}

func TestPaillierGroupRandForEncrypt(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	for i := 0; i < 20; i++ {
		v, err := group.RandForEncrypt()
		require.NoError(t, err)
		require.Equal(t, v.Cmp(group.nd4), -1)
		require.Equal(t, v.Cmp(big.NewInt(0)), 1)
	}
}

func TestPaillierGroupHashNilValues(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	_, err = group.Hash(nil, nil, nil)
	require.Error(t, err)
	_, err = group.Hash(big.NewInt(1), []*big.Int{}, []byte{})
	require.Error(t, err)
	_, err = group.Hash(big.NewInt(1), []*big.Int{nil, nil}, []byte{1, 1})
	require.Error(t, err)
}

func TestPaillierGroupHash(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	tests := []struct {
		u    *big.Int
		e    []*big.Int
		data []byte
		expt *big.Int
	}{
		{u: big.NewInt(1), e: []*big.Int{big.NewInt(1), big.NewInt(1)}, data: []byte{1, 1}, expt: internal.B10("78460077383813730105521336387922347204000654707781568442686111557212361415874")},
		{u: big.NewInt(2), e: []*big.Int{big.NewInt(2), big.NewInt(2)}, data: []byte{2, 2}, expt: internal.B10("25064057611008805877221384832284545038206881116061098969649782860410535162174")},
	}

	for _, tst := range tests {
		hs, err := group.Hash(tst.u, tst.e, tst.data)
		require.NoError(t, err)
		require.Equal(t, hs, tst.expt)
	}
}

func TestPaillierGroupMarshal(t *testing.T) {
	group, err := NewPaillierGroupWithPrimes(testP, testQ)
	require.NoError(t, err)

	bin, err := group.MarshalBinary()
	require.NoError(t, err)
	group2 := new(PaillierGroup)
	err = group2.UnmarshalBinary(bin)
	require.NoError(t, err)
	require.Equal(t, group.n, group2.n)
	require.Equal(t, group.n2, group2.n2)
	require.Equal(t, group.n2d2, group2.n2d2)
	require.Equal(t, group.n2d4, group2.n2d4)
	require.Equal(t, group.g, group2.g)
	require.Equal(t, group.h, group2.h)
	require.Equal(t, group.twoInvTwo, group2.twoInvTwo)
}
