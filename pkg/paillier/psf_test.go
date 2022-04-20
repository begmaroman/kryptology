//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package paillier

import (
	"crypto/elliptic"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/require"

	"gitlab.com/neatfusion/chainfusion/kryptology/internal"
	crypto "gitlab.com/neatfusion/chainfusion/kryptology/pkg/core"
	curves2 "gitlab.com/neatfusion/chainfusion/kryptology/pkg/core/curves"
)

var testPrimes = []*big.Int{
	internal.B10("186141419611617071752010179586510154515933389116254425631491755419216243670159714804545944298892950871169229878325987039840135057969555324774918895952900547869933648175107076399993833724447909579697857041081987997463765989497319509683575289675966710007879762972723174353568113668226442698275449371212397561567"),
	internal.B10("94210786053667323206442523040419729883258172350738703980637961803118626748668924192069593010365236618255120977661397310932923345291377692570649198560048403943687994859423283474169530971418656709749020402756179383990602363122039939937953514870699284906666247063852187255623958659551404494107714695311474384687"),
	internal.B10("130291226847076770981564372061529572170236135412763130013877155698259035960569046218348763182598589633420963942796327547969527085797839549642610021986391589746295634536750785366034581957858065740296991986002552598751827526181747791647357767502200771965093659353354985289411489453223546075843993686648576029043"),
	internal.B10("172938910323633442195852028319756134734590277522945546987913328782597284762767185925315797321999389252040294991952361905020940252121762387957669654615602135429944435719699091344247805645764550860505536884031064967454028383404046221898300153428182409080298694828920944094158777327533157774919783417586902830043"),
	internal.B10("135841191929788643010555393808775051922265083622266098277752143441294911675705272940799534437169053045878247274810449617960047255023823301284034559807472662111224710158898548617194658983006262996831617082584649612602010680423107108651221824216065228161009680618243402116924511141821829055830713600437589058643"),
	internal.B10("179677777376220950493907657233669314916823596507009854134559513388779535023958212632715646194917807302098015450071151245496651913873851032302340489007561121851068326577148680474495447007833318066335149850926605897908761267606415610900931306044455332084757793630487163583451178807470499389106913845684353833379"),
	internal.B10("62649985409697862206708027961094957171873130708493280862148817115812710388878279240372941307490519941098268192630359164091992515623574326498710952492586770923230983753287493884398990474917756375654842939939940915963324175552421981212594421823752854754541693709434365609636589761589816398869727328798680335583"),
	internal.B10("196576931859098680370388202020086631604584490828609819764890020064880575503817891126703473215983239396058738287255240835101797315137072822716923594188151190460588551553676484461393180135097616711975997391550414447010491794087888246885960280296709672609456539741162207414899687167396008233995214434586323322859"),
	internal.B10("271336420864746369701165973306090650688066226258594853124089876839120277465060891854507381090238664515950686049792387028144049076707224579184820539700879884119579186284072404459682082855184644444282438298561112002507411996589407330801765394106772460665497195944412067027079123717579308322520985921886949051399"),
	internal.B10("147653127360336844448178027222853805809444645720500374788954343695331927468524513989671450440433430392339037667457657655958027740671071573403925974795764987870476118984896439440386146680643457835633462311776946902713168513155240275028008685964121441954481847113848701823211862974120297600518927026940189810103"),
	internal.B10("61539010433774119199101441060312213379096965116494840834113311373246794436251480454630309900106802555812462300777026043563820643373439814989443964169335227347638731691284339678436222951965582264570176875078394338903074717434072995072121221264531723385013005031614327462206339323414428493321384497439106152163"),
	internal.B10("311771090987243597109711542316907830756641693311804000593662622484722315782429237915515708860530841821213561483232298821623675096481796856960171671330638042763441430256097782130268494276848432981045602236986861083392706904041234926428759947857376161689191720483868111001987710383245853931937989224732484206639"),
	internal.B10("348545239501897032367950520763624245702184225360238826931782856428685149253861325854706825698843098817604431561258712026020688621010635185480321876001016614912927680387840531641703966894322797491484955817022624047355473480912508041252361257911175397626575812830091471419378132244146077774966527307225203863239"),
	internal.B10("167562983031509383478485987630533113343120902430985961468758712448125734458812918541051012669749885569679178971612428577288632429606851871845164719448590160530844833425628143996971699662729056519326776907622035340086832629206691942750594912221135787534670122007438859975313187460872690748138136170080913902203"),
	internal.B10("151715609132228776595716500435665208768897792993205818803431003524953811539898459230192282642811956896879836518212758893685104146944932088195466999437630114129887975508715417094019351746027667352287673763064246395392591213231796089814648654152625331299642171758052545451706130433176935280325874961374276589763"),
	internal.B10("281712498774102170277967098381151873986368736986748325672760355775943894718315925237789122870763991635031524237638254080973752419302437870447849091185409669906909828874532209010547976564209374430136988588219470076527433259993640332285914706329187116209118972038509278879237122949265824264856530096167843589043"),
	internal.B10("86882427063713590116032012033991745733440719961931885774819345297872782432110706546175706398857226544896860987721577779470479838062106788873559026307646871133570915480684987993282364698928926188640576189281202695899665555602891606955025957497645420156315890379148794822782242384167644977894987285630058930123"),
	internal.B10("83303406464212917441403726886711948278716398972782717472384580707071541544369912289531948826578557956123897261910116726555850408667234850301141318443154703778225305104540324875867615851047711871915209458107086347063530255813116254895432804373554367035028329996279513893337862177371103671113527972705508417219"),
	internal.B10("290829612093510969863838578444630131194824970528125429399090307997156531200557462531776190769158191441614466855963164356672434851525764502180873524299787560160992955274777477308009367164212073773611071813219472273292916120276721541591451163160398750751633065097434700462944540404208636130411713202759646572187"),
	internal.B10("48881643615473281990659967689574873112454227417010573158578046287415357392674453353386274403945930212163960526780980360358370255117866064326375672959460785974850231208253282115124348836379470403659096433419030132737534978624170609788431758477453270578400762995584298785082853409573009591146163658067217132999"),
	internal.B10("47818664065019136841944639898604168570191742429107462510943153778085167306149797958497736138014922106778177497683417470713996340979203175236987691632152128071256018368891463388744514315997309312144264057334961479235114340091423812710466596081259537323405527816634204224641066174554915788023121121924554823463"),
	internal.B10("229695065817346126758526483359337260282925372883465036895664320607569899180246065431164369223444026964554195802821338287119074827091354255558249504915527499047398698041873875019622138440848556549357174461846992529556315682586788137744896985847052668283284231628825924370859640129811142861116994552829398428647"),
	internal.B10("100501115016957347491693508757253443864758446032047524096020585354104983606736759639044367167134409576092528219013168507381959241052976704837620234061351712684500077849808223040972825725745511581504906610633548112115513604053190610668096089811015493012026572475283305559529666099836493252485826156659750294903"),
	internal.B10("164941338210872461448879529698900150056451305424623398039343691654768566536491493438826728710972441042226712374570117138883019423322602098706113298908005378303473844839971995715847918643285222217768344335264383514921181158565529236124115589719970140511822410990649549555047928093673140752570788415674868532299"),
	internal.B10("277037199251333188171108034082127252450960810846571117481542098050121457972964006392527344163695411986229107011168411232117984760439307440561490229321182283823299859836750264962218540927582605520434969388646847458788766216835350519741512353041653865564337457599778511921159510170311560556844284028160928114623"),
	internal.B10("194450633495795999995837828580097111229016136925345956148788562473415774074431957758705067019578300241653926511426134047652491974620284426575921711048247821582093564387999309993254763749991516361193554847964638949731507356038181346481870018202492098453036116472375750355687853028597643560794156133662678349939"),
	internal.B10("351287943170075259292767465687447861777186026969543801283411356809391771346213158326614410370157474105344692424346410925411240089238093158848815209147605381454294661108047095253146499393310219242924552687094316959878415907497273176683394122976929775532753961555304244867490393116346360677109958055297215711587"),
	internal.B10("329970582937843908299463472795994928703202360293919677760100619380642134736439176597341134222679061949935544692834943628667398294307004076774417457697130314341974849843695836050603685013468031012892094273233016929045028941716224648802422408386216033754532303003405690778077639489173685122357063674177077611499"),
	internal.B10("67751546105580063387575764356375682499165422473383503143930633584920975946879807021875353514236996076344028719391905234977223693643926924731304657199486141030504275775023186923364159168130612275534168246529309247449138607249407760246378829338068736888203134857601657561860157938495777271164458736576560502603"),
	internal.B10("276043923868350639738966705196129285523536747369492013710841410915407411458158268634302674024358477700030814139419613881758439643092328709376796555454484423864587139181985503560495790018232370315219082876142282958894264284344738294415199758590186234114829175455336589153989920707778566032047921277945163061363"),
	internal.B10("62028909880050184794454820320289487394141550306616974968340908736543032782344593292214952852576535830823991093496498970213686040280098908204236051130358424961175634703281821899530101130244725435470475135483879784963475148975313832483400747421265545413510460046067002322131902159892876739088034507063542087523"),
	internal.B10("321804071508183671133831207712462079740282619152225438240259877528712344129467977098976100894625335474509551113902455258582802291330071887726188174124352664849954838358973904505681968878957681630941310372231688127901147200937955329324769631743029415035218057960201863908173045670622969475867077447909836936523"),
	internal.B10("52495647838749571441531580865340679598533348873590977282663145916368795913408897399822291638579504238082829052094508345857857144973446573810004060341650816108578548997792700057865473467391946766537119012441105169305106247003867011741811274367120479722991749924616247396514197345075177297436299446651331187067"),
	internal.B10("118753381771703394804894143450628876988609300829627946826004421079000316402854210786451078221445575185505001470635997217855372731401976507648597119694813440063429052266569380936671291883364036649087788968029662592370202444662489071262833666489940296758935970249316300642591963940296755031586580445184253416139"),
}

func TestGenerateChallengesWorks(t *testing.T) {
	curves := []elliptic.Curve{btcec.S256(), elliptic.P256()}
	for _, curve := range curves {
		// dummy secret based on curve
		y, _ := curves2.NewScalarBaseMult(curve, big.NewInt(3))

		for i := 0; i < 5; i++ {
			for j := 0; j < 5; j++ {
				// Compute N from test primes
				skN := new(big.Int).Mul(testPrimes[i], testPrimes[j])
				x, err := generateChallenges(curve.Params(), skN, uint32(i+1), y)

				require.NoError(t, err)
				for _, xj := range x {
					require.NotNil(t, xj)
					require.Greater(t, xj.Cmp(crypto.Zero), 0)
					require.Equal(t, xj.Cmp(skN), -1)
				}
			}
		}
	}
}

// tests whether the hash function can still produce valid challenges
// even when the modulus is smaller than the hash output
func TestGenerateChallengesPrimeN(t *testing.T) {
	curves := []elliptic.Curve{btcec.S256(), elliptic.P256()}
	n := []*big.Int{
		internal.B10("680564733841876926926749214863536724007"),
		internal.B10("1234345830644315716128223123383371693999"),
		internal.B10("358070498390900219760227294443948492156530525739357363711230524749453568134007"),
		internal.B10("409819537231165473932776844223512813127760876374228481246566335070809195677439"),
		internal.B10("336327054820888403283842064345570507895192245801107954728200717775133442039527"),
		internal.B10("353526063197730551176241127281213353808518592628930654494044427064787696719527"),
	}

	for _, curve := range curves {
		// dummy secret based on curve
		y, _ := curves2.NewScalarBaseMult(curve, big.NewInt(3))
		for i := 0; i < 5; i++ {
			for j := 0; j < 5; j++ {
				x, err := generateChallenges(curve.Params(), n[i], uint32(j+1), y)

				require.NoError(t, err)
				for _, xj := range x {
					require.NotNil(t, xj)
					require.Greater(t, xj.Cmp(crypto.Zero), 0)
				}
			}
		}
	}
}

func TestGenerateChallengesNilInputs(t *testing.T) {
	y, _ := curves2.NewScalarBaseMult(elliptic.P256(), big.NewInt(1))

	_, err := generateChallenges(nil, nil, 0, nil)
	require.Error(t, err)
	_, err = generateChallenges(elliptic.P256().Params(), nil, 0, nil)
	require.Error(t, err)
	_, err = generateChallenges(elliptic.P256().Params(), big.NewInt(0), 0, nil)
	require.Error(t, err)
	_, err = generateChallenges(elliptic.P256().Params(), big.NewInt(1), 1, nil)
	require.Error(t, err)
	_, err = generateChallenges(elliptic.P256().Params(), big.NewInt(1), 1, y)
	require.Error(t, err)
	_, err = generateChallenges(elliptic.P256().Params(), big.NewInt(1), 1, y)
	require.Error(t, err)
	_, err = generateChallenges(elliptic.P256().Params(), big.NewInt(255), 1, y)
	require.NoError(t, err)
}

func TestPsfProofParams_Prove(t *testing.T) {
	// RSA primes for testing
	sk, _ := NewSecretKey(
		// 75-digit random primes from Wolfram-Alpha
		internal.B10("110045198697022997120409435651962875820936327127306040565577217116705932648687"),
		internal.B10("95848033199746534486927143950536999279071340697368502822602282152563330640779"))
	smallSk, _ := NewSecretKey(big.NewInt(13), big.NewInt(11))

	// Some points for testing
	k := internal.B10("270988338908697209412444309907441365656383309727758604622908325428179708750")
	Qp256, _ := curves2.NewScalarBaseMult(elliptic.P256(), k)
	Qs256, _ := curves2.NewScalarBaseMult(btcec.S256(), k)
	pi := uint32(4)

	tests := []struct {
		name              string
		in                *PsfProofParams
		expectedError     error
		expectedResultLen int
	}{
		// Positive tests
		{"positive: p256, small numbers",
			&PsfProofParams{elliptic.P256(), smallSk, 1001, Qp256},
			nil,
			PsfProofLength,
		},
		{"positive: p256, large numbers",
			&PsfProofParams{elliptic.P256(), sk, pi, Qp256},
			nil,
			PsfProofLength,
		},
		{"positive: s256, large numbers",
			&PsfProofParams{btcec.S256(), sk, pi, Qs256},
			nil,
			PsfProofLength,
		},

		// Nil params
		{"negative: ",
			&PsfProofParams{btcec.S256(),
				sk,
				pi,
				Qs256},
			nil,
			PsfProofLength,
		},
		{"negative: proof params are nil",
			&PsfProofParams{nil,
				sk,
				pi,
				Qs256},
			internal.ErrNilArguments,
			0,
		},
		{"negative: SecretKey is nil",
			&PsfProofParams{btcec.S256(),
				nil,
				pi,
				Qs256},
			internal.ErrNilArguments,
			0,
		},
		{"negative: y is nil",
			&PsfProofParams{btcec.S256(),
				sk,
				0,
				Qs256},
			internal.ErrNilArguments,
			0,
		},
		{"negative: Pi is nil",
			&PsfProofParams{btcec.S256(),
				sk,
				pi,
				nil},
			internal.ErrNilArguments,
			0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// test
			result, err := test.in.Prove()

			// Verify the results are as expected
			require.Equal(t, test.expectedError, err)
			require.Len(t, result, test.expectedResultLen)
		})
	}

}

// Test that Range2Proof can be marshaled and unmarshaled correctly
func TestPsfProof_MarshalJSON(t *testing.T) {
	// Generate some proof
	sk, _ := NewSecretKey(
		internal.B10("110045198697022997120409435651962875820936327127306040565577217116705932648687"),
		internal.B10("95848033199746534486927143950536999279071340697368502822602282152563330640779"))
	Q, _ := curves2.NewScalarBaseMult(elliptic.P256(),
		internal.B10("270988338908697209412444309907441365656383309727758604622908325428179708750"))
	params := &PsfProofParams{
		elliptic.P256(), sk,
		1,
		Q,
	}
	proof, err := params.Prove()
	require.NoError(t, err)
	require.NotNil(t, proof)

	// Marshal
	testJSON, err := json.Marshal(proof)
	require.NoError(t, err)
	require.NotNil(t, testJSON)

	var unmarshaled PsfProof
	err = json.Unmarshal(testJSON, &unmarshaled)
	require.NoError(t, err)

	// Test for equality
	require.Len(t, ([]*big.Int)(unmarshaled), len(([]*big.Int)(proof)))
	for i := range proof {
		require.Equal(t, proof[i], unmarshaled[i])
	}
}

// Tests for Verify
// prove/verify round trip works
// modifying any parameter causes verify to fail
func TestPsfProofWorks(t *testing.T) {
	// RSA primes for testing
	sk, _ := NewSecretKey(
		// 75-digit random primes from Wolfram-Alpha
		internal.B10("110045198697022997120409435651962875820936327127306040565577217116705932648687"),
		internal.B10("95848033199746534486927143950536999279071340697368502822602282152563330640779"))

	// Some points for testing
	k := internal.B10("270988338908697209412444309907441365656383309727758604622908325428179708750")
	Qp256, _ := curves2.NewScalarBaseMult(elliptic.P256(), k)
	pi := uint32(2)

	proveParams := &PsfProofParams{
		Curve:     elliptic.P256(),
		SecretKey: sk,
		Pi:        pi,
		Y:         Qp256,
	}
	proof, _ := proveParams.Prove()
	verifyParams := &PsfVerifyParams{
		Curve:     elliptic.P256(),
		PublicKey: &sk.PublicKey,
		Pi:        pi,
		Y:         Qp256,
	}
	require.NoError(t, proof.Verify(verifyParams))
}
