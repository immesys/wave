package iapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

var ErrDecryptBodyMalformed = errors.New("body is malformed")

func AttestationBodySchemeFor(ex *asn1.External) AttestationBodyScheme {
	if ex.OID.Equal(serdes.UnencryptedBodyOID) {
		return &PlaintextBodyScheme{}
	}
	if ex.OID.Equal(serdes.WR1BodyOID) {
		return &WR1BodyScheme{}
	}
	return &UnsupportedBodyScheme{}
}

// plaintext
var _ AttestationBodyScheme = &PlaintextBodyScheme{}

type PlaintextBodyScheme struct {
	//CanonicalForm *asn1.External
}

var PLAINTEXTBODYSCHEME = &PlaintextBodyScheme{}

func NewPlaintextBodyScheme() *PlaintextBodyScheme {
	return &PlaintextBodyScheme{}
}
func (pt *PlaintextBodyScheme) Supported() bool {
	return true
}
func (pt *PlaintextBodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation, inextra interface{}) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	rv := canonicalForm.TBS.Body.Content.(serdes.AttestationBody)
	return &rv, nil, nil
}
func (pt *PlaintextBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	return intermediateForm, nil, nil
}

// unsupported
var _ AttestationBodyScheme = &UnsupportedBodyScheme{}

type UnsupportedBodyScheme struct {
}

func (u *UnsupportedBodyScheme) Supported() bool {
	return false
}
func (u *UnsupportedBodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation, inextra interface{}) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	return nil, nil, fmt.Errorf("body scheme is unsupported")
}
func (u *UnsupportedBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	return nil, nil, fmt.Errorf("body scheme is unsupported")
}

// wr1
type WR1DecryptionContext interface {
	WR1VerifierBodyKey(ctx context.Context) []byte
	WR1ProverBodyKey(ctx context.Context) []byte
	//WR1EntityFromHash(ctx context.Context, hash HashSchemeInstance, loc LocationSchemeInstance) (*Entity, error)
	WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, delegable bool, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
	WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
	WR1DirectDecryptionKey(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
	WR1AttesterDirectDecryptionKey(ctx context.Context, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type WR1BodyScheme struct {
}

type WR1Extra struct {
	Partition       [][]byte
	VerifierBodyKey []byte
	ProverBodyKey   []byte

	EnvelopeKey []byte
	//For NameDecl only
	Namespace         HashSchemeInstance
	NamespaceLocation LocationSchemeInstance
}

func (w *WR1BodyScheme) Supported() bool {
	return true
}

var XXKey SlottedSecretKey

func (w *WR1BodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation, inextra interface{}) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	//fmt.Printf("dc AA %x\n", canonicalForm.OuterSignature.Content.(serdes.Ed25519OuterSignature).Signature[0:4])
	// bf := make([]byte, 8000)
	// count := runtime.Stack(bf, false)
	// bf = bf[:count]
	//fmt.Printf("stack: %s\n", string(bf))
	incomingExtra, ok := inextra.(*WR1Extra)
	if !ok {
		incomingExtra = nil
	}
	wr1body, ok := canonicalForm.TBS.Body.Content.(serdes.WR1BodyCiphertext)
	if !ok {
		//fmt.Printf("dc A1\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	wr1dctx, ok := dc.(WR1DecryptionContext)
	if !ok {
		//fmt.Printf("dc failed\n")
		return nil, nil, nil
	}
	subjectHI := HashSchemeInstanceFor(&canonicalForm.TBS.Subject)
	if !subjectHI.Supported() {
		fmt.Printf("wrong HI\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	//Step 0: if there is a symmetric key in the decrytion context we should use that
	vbody := serdes.WR1VerifierBody{}
	attverifierkey := wr1dctx.WR1VerifierBodyKey(ctx)
	//fmt.Printf("dc BB\n")
	if attverifierkey != nil {
		//fmt.Printf("found att verifier key %d\n", len(attverifierkey))
		verifierBodyKey := attverifierkey[:16]
		verifierBodyNonce := attverifierkey[16:]
		verifierBodyDER, ok := aesGCMDecrypt(verifierBodyKey, wr1body.VerifierBodyCiphertext, verifierBodyNonce)
		if !ok {
			//fmt.Printf("case B\n")
			return nil, nil, ErrDecryptBodyMalformed
		}
		trailing, err := asn1.Unmarshal(verifierBodyDER, &vbody)
		if err != nil || len(trailing) != 0 {
			//fmt.Printf("case C\n")
			return nil, nil, ErrDecryptBodyMalformed
		}
		rv := &serdes.AttestationBody{
			VerifierBody: vbody.AttestationVerifierBody,
		}
		return rv, nil, nil
	}
	//We did not have an attestation verifier key in the decryption context, try
	//to decrypt in the prover role

	//fmt.Printf("dc A\n")

	//Step 1: decode the label
	//First try get the envelope key using asymmetric direct encryption
	var envelopeKey []byte
	var bodyKeys []byte
	//Actually first check for prover key in dctx
	explicitProverBodyKey := wr1dctx.WR1ProverBodyKey(ctx)
	if explicitProverBodyKey != nil {
		envelopeKey = explicitProverBodyKey[:28]
	}
	if incomingExtra != nil && incomingExtra.EnvelopeKey != nil {
		envelopeKey = incomingExtra.EnvelopeKey
	}
	if envelopeKey == nil {
		err = wr1dctx.WR1DirectDecryptionKey(ctx, subjectHI, func(k EntitySecretKeySchemeInstance) bool {
			var err error
			envelopeKey, err = k.DecryptMessage(ctx, wr1body.EnvelopeKey_Curve25519)
			if err == nil {
				return false
			}
			return true
		})
		if err != nil {
			fmt.Printf("dc D\n")
			return nil, nil, err
		}
	}
	if envelopeKey == nil {
		err = wr1dctx.WR1AttesterDirectDecryptionKey(ctx, func(k EntitySecretKeySchemeInstance) bool {
			var err error
			allkeys, err := k.DecryptMessage(ctx, wr1body.EnvelopeKey_Curve25519Attester)
			if err != nil {
				return true
			}
			envelopeKey = allkeys[:28]
			bodyKeys = allkeys[28:]
			fmt.Printf("attester direct worked\n")
			return false
		})
		if err != nil {
			fmt.Printf("dc 2D\n")
			return nil, nil, err
		}
	}
	//fmt.Printf("dc B\n")
	if envelopeKey == nil {
		//fmt.Printf("XXXXXXX dc C\n")
		//Try using label secrets
		err := wr1dctx.WR1IBEKeysForPartitionLabel(ctx, subjectHI, func(k EntitySecretKeySchemeInstance) bool {
			var err error
			envelopeKey, err = k.DecryptMessage(ctx, wr1body.EnvelopeKey_IBE_BLS12381)
			if err == nil {
				return false
			}
			return true
		})
		if err != nil {
			return nil, nil, err
		}
	}
	if envelopeKey == nil {
		fmt.Printf("dc no label\n")
		return nil, nil, nil
	}

	//The key is actually 16 bytes of AES key + 12 bytes of GCM nonce
	if len(envelopeKey) != 16+12 {
		fmt.Printf("dc E\n")
		return nil, nil, ErrDecryptBodyMalformed
	}

	//Lets actually decrypt the envelope DER
	envelopeDER, ok := aesGCMDecrypt(envelopeKey[:16], wr1body.EnvelopeCiphertext, envelopeKey[16:])
	if !ok {
		fmt.Printf("dc F\n")
		return nil, nil, ErrDecryptBodyMalformed
	}

	envelope := serdes.WR1Envelope{}
	trailing, err := asn1.Unmarshal(envelopeDER, &envelope)
	if err != nil || len(trailing) != 0 {
		//fmt.Printf("dc G\n")
		return nil, nil, ErrDecryptBodyMalformed
	}

	//strip empty strings
	realpartition := make([][]byte, 20)
	for idx, e := range envelope.Partition {
		if len(e) > 0 {
			realpartition[idx] = e
		}
	}

	//fmt.Printf("dc2 1\n")
	//We know the partition labels now
	rvextra := &WR1Extra{Partition: realpartition, EnvelopeKey: envelopeKey}
	extra = rvextra
	if explicitProverBodyKey != nil {
		bodyKeys = explicitProverBodyKey[28:]
	}
	if bodyKeys == nil {
		//Try decrypt with those labels
		err = wr1dctx.WR1OAQUEKeysForContent(ctx, subjectHI, false, realpartition, func(k SlottedSecretKey) bool {
			var err error
			XXKey = k
			bodyKeys, err = k.DecryptMessageAsChild(ctx, envelope.BodyKeys_OAQUE, realpartition)
			if err == nil {
				return false
			}
			return true
		})
		if err != nil {
			//Why would we get an error here?
			panic(err)
		}
	}
	if bodyKeys == nil {
		//We could not decrypt the dot. Just return with whatever we have
		fmt.Printf("no inner keys\n")
		return nil, extra, nil
	}
	if len(bodyKeys) != 16+12+16+12 {
		fmt.Printf("lbk\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	proverBodyKey := bodyKeys[0:16]
	proverBodyNonce := bodyKeys[16:28]
	verifierBodyKey := bodyKeys[28:44]
	verifierBodyNonce := bodyKeys[44:56]

	pbody := serdes.WR1ProverBody{}

	proverBodyDER, ok := aesGCMDecrypt(proverBodyKey, wr1body.ProverBodyCiphertext, proverBodyNonce)
	if !ok {
		fmt.Printf("keyfail 1\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	verifierBodyDER, ok := aesGCMDecrypt(verifierBodyKey, wr1body.VerifierBodyCiphertext, verifierBodyNonce)
	if !ok {
		fmt.Printf("keyfail 2\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	trailing, err = asn1.Unmarshal(proverBodyDER, &pbody)
	if err != nil || len(trailing) != 0 {
		fmt.Printf("keyfail 3\n")
		return nil, nil, ErrDecryptBodyMalformed
	}
	trailing, err = asn1.Unmarshal(verifierBodyDER, &vbody)
	if err != nil || len(trailing) != 0 {
		fmt.Printf("keyfail 4\n")
		fmt.Printf("trailing: %x\n", trailing)
		fmt.Printf("err: %v\n", err)
		return nil, nil, ErrDecryptBodyMalformed
	}
	rv := &serdes.AttestationBody{
		VerifierBody:          vbody.AttestationVerifierBody,
		ProverPolicyAddendums: pbody.Addendums,
		ProverExtensions:      pbody.Extensions,
	}
	if explicitProverBodyKey == nil {
		explicitProverBodyKey = make([]byte, 28*3)
		copy(explicitProverBodyKey[0:28], envelopeKey)
		copy(explicitProverBodyKey[28:], bodyKeys)
	}
	rvextra.VerifierBodyKey = bodyKeys[28:56] //include nonce
	rvextra.ProverBodyKey = explicitProverBodyKey
	//fmt.Printf("dc Z\n")
	return rv, rvextra, nil
}

type WR1BodyEncryptionContext interface {
	BodyEncryptionContext
	WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, delegable bool, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
	WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
	WR1EntityFromHash(ctx context.Context, hash HashSchemeInstance, loc LocationSchemeInstance) (*Entity, error)
}

func isPolicyE2EE(p PolicySchemeInstance) (HashSchemeInstance, LocationSchemeInstance, bool) {
	rtree, ok := p.(*RTreePolicy)
	if !ok {
		return nil, nil, false
	}
	for _, s := range rtree.SerdesForm.Statements {
		hi := HashSchemeInstanceFor(&s.PermissionSet)
		if hi.Supported() && hi.MultihashString() == consts.WaveBuiltinPSET {
			if len(s.Permissions) == 1 && s.Permissions[0] == consts.WaveBuiltinE2EE {
				loc := LocationSchemeInstanceFor(&rtree.SerdesForm.NamespaceLocation)
				return rtree.WR1DomainEntity(), loc, true
			}
		}
	}
	return nil, nil, false
}

func (w *WR1BodyScheme) EncryptBody(ctx context.Context, ecp BodyEncryptionContext, attester *EntitySecrets, subject *Entity, intermediateForm *serdes.WaveAttestation, policy PolicySchemeInstance) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	//fmt.Printf("encrypt body called\n")
	ec := ecp.(WR1BodyEncryptionContext)
	//Step 0 generate the WR1 keys
	// - IBE key using the domain visibility from the policy
	// - OAQUE key using the WR1 partition from the entity
	// - TODO: in-order parent dot key delegation
	//  basically we are only supporting same or broadening delegation in/out of order
	//  to support narrowing in-order we would want to include extra WR1 keys in the dot
	plaintextBody := intermediateForm.TBS.Body.Content.(serdes.AttestationBody)
	//Ok now lets generate the symmetric encryption keys
	bodyKeys := make([]byte, 16+12+16+12)
	if _, e := rand.Read(bodyKeys); e != nil {
		panic(e)
	}
	visibilityEntity := policy.WR1DomainEntity()
	var visibilityID string = "$GLOBAL"
	if visibilityEntity != nil {
		visibilityID = visibilityEntity.MultihashString()
	}
	bodySlots, err := CalculateWR1Partition(plaintextBody.VerifierBody.Validity.NotBefore,
		plaintextBody.VerifierBody.Validity.NotAfter,
		policy.WR1PartitionPrefix())
	if err != nil {
		return nil, nil, err
	}
	visibilityParams, err := subject.WR1_DomainVisiblityParams()
	if err != nil {
		return nil, nil, err
	}
	visibilityKey, err := visibilityParams.GenerateChildKey(ctx, []byte(visibilityID))
	if err != nil {
		return nil, nil, err
	}
	directKey1, err := subject.WR1_DirectEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	directKey2, err := attester.Entity.WR1_DirectEncryptionKey()
	if err != nil {
		return nil, nil, err
	}
	bodyParams, err := subject.WR1_BodyParams()
	if err != nil {
		return nil, nil, err
	}
	oaqueBodyKey, err := bodyParams.GenerateChildKey(ctx, bodySlots)
	if err != nil {
		return nil, nil, err
	}

	//Ok now we have the key material we need to encrypt. Lets generate the delegated key material
	delegatedVisibilityKey, err := attester.WR1LabelKey(ctx, []byte(visibilityID))
	if err != nil {
		fmt.Printf("K 3\n")
		return nil, nil, err
	}

	e2eNS, e2eNSLoc, isE2E := isPolicyE2EE(policy)

	//Get the bundle, but it is empty (no keys)
	partitions, delegatedBundle, err := CalculateEmptyKeyBundleEntries(plaintextBody.VerifierBody.Validity.NotBefore,
		plaintextBody.VerifierBody.Validity.NotAfter,
		policy.WR1PartitionPrefix())
	if err != nil {
		fmt.Printf("K 2\n")
		return nil, nil, err
	}

	var e2eDelegatedBundle []serdes.BLS12381OAQUEKeyringBundleEntry
	if isE2E {
		var err error
		_, e2eDelegatedBundle, err = CalculateEmptyKeyBundleEntries(plaintextBody.VerifierBody.Validity.NotBefore,
			plaintextBody.VerifierBody.Validity.NotAfter,
			policy.WR1PartitionPrefix())
		if err != nil {
			fmt.Printf("K 1\n")
			return nil, nil, err
		}
	}
	e2eKeyOkay := make([]bool, len(e2eDelegatedBundle))

	//Generating these delegated keys is a bit of a pain. Sequentially its about 1.5s on my machine.
	//If we split it over multiple cores it goes down to about 250 ms
	then := time.Now()
	if true {
		workers := runtime.NumCPU()
		batches := make([][]int, workers)
		numperworker := len(partitions) / workers
		if numperworker == 0 {
			numperworker = 1
		}
		for i := 0; i < workers; i++ {
			batch := []int{}
			if i == workers-1 {
				for k := i * numperworker; k < len(partitions); k++ {
					batch = append(batch, k)
				}

			} else {
				for k := i * numperworker; k < (i+1)*numperworker && k < len(partitions); k++ {
					batch = append(batch, k)
				}
			}
			batches[i] = batch
		}
		wg := sync.WaitGroup{}
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func(i int) {
				batchpartitions := make([][][]byte, 0, len(batches[i]))
				if len(batches[i]) == 0 {
					wg.Done()
					return
				}
				for _, k := range batches[i] {
					batchpartitions = append(batchpartitions, partitions[k])
				}
				kz, err := attester.CalculateWR1Batch(batchpartitions, true)
				if err != nil {
					panic(err)
				}
				kzidx := 0
				for _, idx := range batches[i] {
					cf := kz[kzidx].SecretCanonicalForm()
					kzidx += 1
					delegatedBundle[idx].Key = cf.Private.Content.(serdes.EntitySecretOQAUE_BLS12381_s20)
					if isE2E {
						//Also try generate the e2e key, which is in the namespace system
						var sk SlottedSecretKey
						ec.WR1OAQUEKeysForContent(ctx, e2eNS, true, partitions[idx], func(k SlottedSecretKey) bool {
							esk, err := k.GenerateChildSecretKey(ctx, partitions[idx], true)
							if err != nil {
								panic(err)
							}
							sk = esk.(SlottedSecretKey)
							return false
						})
						if sk != nil {
							e2eKeyOkay[idx] = true
							//fmt.Printf("Delegated NS key %s was ok\n", WR1PartitionToIntString(partitions[idx]))
							cf := sk.SecretCanonicalForm()
							e2eDelegatedBundle[idx].Key = cf.Private.Content.(serdes.EntitySecretOQAUE_BLS12381_s20)
						}
					}
				}
				wg.Done()
			}(i)
		}
		wg.Wait()
		// for l, ll := range delegatedBundle {
		// 	//	fmt.Printf("%d : %p\n", l, ll)
		// }
	} else {
		//then := time.Now()
		//Old method
		const workers = 8 //TODO32
		togenerate := make([][]int, workers)
		for i := 0; i < len(partitions); i++ {
			togenerate[i%workers] = append(togenerate[i%workers], i)
		}
		wg := sync.WaitGroup{}
		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func(i int) {
				for _, idx := range togenerate[i] {
					k, err := attester.WR1BodyKey(ctx, partitions[idx], true)
					if err != nil {
						panic(err)
					}
					//This is a keyring entry, we need to extract just the oaque private key
					cf := k.SecretCanonicalForm()
					delegatedBundle[idx].Key = cf.Private.Content.(serdes.EntitySecretOQAUE_BLS12381_s20)

					if isE2E {
						panic("not expecting this")
						//Also try generate the e2e key, which is in the namespace system
						var sk SlottedSecretKey
						ec.WR1OAQUEKeysForContent(ctx, e2eNS, true, partitions[idx], func(k SlottedSecretKey) bool {
							esk, err := k.GenerateChildSecretKey(ctx, partitions[idx], true)
							if err != nil {
								panic(err)
							}
							sk = esk.(SlottedSecretKey)
							return false
						})
						if sk != nil {
							e2eKeyOkay[idx] = true
							//fmt.Printf("Delegated NS key %s was ok\n", WR1PartitionToIntString(partitions[idx]))
							cf := sk.SecretCanonicalForm()
							e2eDelegatedBundle[idx].Key = cf.Private.Content.(serdes.EntitySecretOQAUE_BLS12381_s20)
						}
					}
				}
				wg.Done()
			}(i)
		}
		wg.Wait()
		//fmt.Printf("slow method took %s\n", time.Since(then))
	}
	_ = then

	includeE2Ebundle := false

	var e2eBundle serdes.BLS12381OAQUEKeyringBundle
	var e2eVisiblityKey serdes.WR1DomainVisibilityKey_IBE_BLS12381
	if isE2E {
		nsEnt, err := ec.WR1EntityFromHash(ctx, e2eNS, e2eNSLoc)
		if err != nil {
			fmt.Printf("K 4\n")
			return nil, nil, wve.ErrW(wve.InvalidE2EEGrant, "could not look up namespace entity", err)
		}
		expected := []byte(nsEnt.Keccak256HI().MultihashString())
		var foundVisKey bool
		ec.WR1IBEKeysForPartitionLabel(ctx, e2eNS, func(k EntitySecretKeySchemeInstance) bool {
			id := k.Public().(*EntityKey_IBE_BLS12381).ID
			if bytes.Equal(id, expected) {
				cf := k.SecretCanonicalForm()
				foundVisKey = true
				e2eVisiblityKey = serdes.WR1DomainVisibilityKey_IBE_BLS12381(*cf)
				return false
			} else {
			}
			return true
		})
		if !foundVisKey {
			return nil, nil, wve.Err(wve.InvalidE2EEGrant, "could find namespace visibility key")
		}
		nsparams, err := nsEnt.WR1_BodyParams()
		if err != nil {
			return nil, nil, err
		}
		e2eBundle.Params = nsparams.(*EntityKey_OAQUE_BLS12381_S20_Params).Params.Marshal(wkdIBECompressed)
		entries := []serdes.BLS12381OAQUEKeyringBundleEntry{}
		for idx, ok := range e2eKeyOkay {
			if ok {
				entries = append(entries, e2eDelegatedBundle[idx])
				includeE2Ebundle = true
			}
		}
		e2eBundle.Entries = entries
	}
	// for idx, p := range partitions {
	// 	fmt.Printf("granted key %d: %s\n", idx, WR1PartitionToIntString(p))
	// }
	sparams, err := attester.Entity.WR1_BodyParams()
	if err != nil {
		panic(err)
	}
	params := sparams.(*EntityKey_OAQUE_BLS12381_S20_Params).SerdesForm.Key.Content.(serdes.EntityParamsOQAUE_BLS12381_s20)
	bundleCF := serdes.BLS12381OAQUEKeyringBundle{
		Params:  params,
		Entries: delegatedBundle,
	}
	proverBodyKey := bodyKeys[0:16]
	proverBodyNonce := bodyKeys[16:28]
	verifierBodyKey := bodyKeys[28:44]
	verifierBodyNonce := bodyKeys[44:56]
	ciphertext := &serdes.WR1BodyCiphertext{}
	envelope := &serdes.WR1Envelope{}
	proverBody := &serdes.WR1ProverBody{}
	verifierBody := &serdes.WR1VerifierBody{}

	//Copy the fields
	proverBody.Addendums = plaintextBody.ProverPolicyAddendums
	dvkSCF := delegatedVisibilityKey.SecretCanonicalForm()
	proverBody.Addendums = append(proverBody.Addendums, asn1.NewExternal(serdes.WR1DomainVisibilityKey_IBE_BLS12381(*dvkSCF)))
	proverBody.Addendums = append(proverBody.Addendums, asn1.NewExternal(bundleCF))
	if isE2E && includeE2Ebundle {
		proverBody.Addendums = append(proverBody.Addendums, asn1.NewExternal(e2eBundle))
		proverBody.Addendums = append(proverBody.Addendums, asn1.NewExternal(e2eVisiblityKey))
	}
	proverBody.Extensions = plaintextBody.ProverExtensions
	verifierBody.AttestationVerifierBody = plaintextBody.VerifierBody

	//Get the DER
	proverBodyDER, err := asn1.Marshal(*proverBody)
	if err != nil {
		return nil, nil, err
	}

	verifierBodyDER, err := asn1.Marshal(*verifierBody)
	if err != nil {
		return nil, nil, err
	}

	//Encrypt the DER using the given keys
	ciphertext.ProverBodyCiphertext = aesGCMEncrypt(proverBodyKey, proverBodyDER, proverBodyNonce)
	ciphertext.VerifierBodyCiphertext = aesGCMEncrypt(verifierBodyKey, verifierBodyDER, verifierBodyNonce)

	//Create the OAQUE ciphertext
	envelope.BodyKeys_OAQUE, err = oaqueBodyKey.EncryptMessage(ctx, bodyKeys)
	if err != nil {
		return nil, nil, err
	}
	envelope.Partition = bodySlots

	//Get the envelope DER
	envelopeDER, err := asn1.Marshal(*envelope)
	if err != nil {
		return nil, nil, err
	}

	//Generate a key for the envelope
	envelopeSymKey := make([]byte, 16+12)
	rand.Read(envelopeSymKey)

	//Encrypt under the destination's curve25519 key
	ciphertext.EnvelopeKey_Curve25519, err = directKey1.EncryptMessage(ctx, envelopeSymKey)
	if err != nil {
		return nil, nil, err
	}
	attesterKeyMaterial := []byte{}
	attesterKeyMaterial = append(attesterKeyMaterial, envelopeSymKey...)
	attesterKeyMaterial = append(attesterKeyMaterial, bodyKeys...)
	ciphertext.EnvelopeKey_Curve25519Attester, err = directKey2.EncryptMessage(ctx, attesterKeyMaterial)
	if err != nil {
		return nil, nil, err
	}

	//Encrypt under the destinations IBE key
	ciphertext.EnvelopeKey_IBE_BLS12381, err = visibilityKey.EncryptMessage(ctx, envelopeSymKey)
	if err != nil {
		return nil, nil, err
	}
	ciphertext.EnvelopeCiphertext = aesGCMEncrypt(envelopeSymKey[:16], envelopeDER, envelopeSymKey[16:])
	//Return the intermediate form with the body replaced
	intermediateForm.TBS.Body = asn1.NewExternal(*ciphertext)
	explicitProverBodyKey := make([]byte, 28*3)
	copy(explicitProverBodyKey[0:28], envelopeSymKey)
	copy(explicitProverBodyKey[28:], bodyKeys)

	rvextra := &WR1Extra{
		Partition:       bodySlots,
		VerifierBodyKey: bodyKeys[28:56],
		ProverBodyKey:   explicitProverBodyKey,
	}
	return intermediateForm, rvextra, nil
}

type PSKExtra struct {
	VerifierBodyKey []byte
}
type PSKBodyDecryptionContext interface {
	GetDecryptPSK(ctx context.Context, dst HashScheme, public EntityKeySchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type PSKBodyEncryptionContext interface {
	GetEncryptPSK(ctx context.Context, body *serdes.WaveAttestation, onResult func(k EntitySecretKeySchemeInstance) bool) error
}
type PSKBodyScheme struct {
	CanonicalForm *asn1.External
}

func (psk *PSKBodyScheme) Supported() bool {
	return true
}
func (psk *PSKBodyScheme) DecryptBody(ctx context.Context, dc BodyDecryptionContext, canonicalForm *serdes.WaveAttestation) (decodedForm *serdes.AttestationBody, extra interface{}, err error) {
	ciphertext := canonicalForm.TBS.Body.Content.(serdes.PSKBodyCiphertext)
	pk, err := EntityKeySchemeInstanceFor(&ciphertext.EncryptedUnder)
	if err != nil {
		return nil, nil, err
	}
	subject := HashSchemeFor(canonicalForm.TBS.Subject)
	pskdc := dc.(PSKBodyDecryptionContext)
	decodedForm = nil
	err = fmt.Errorf("no suitable PSK found")
	pskdc.GetDecryptPSK(ctx, subject, pk, func(k EntitySecretKeySchemeInstance) bool {
		der, serr := k.DecryptMessage(ctx, ciphertext.AttestationBodyCiphetext)
		if serr == nil {
			rv := serdes.AttestationBody{}
			trailing, serr := asn1.Unmarshal(der, rv)
			if serr != nil {
				err = serr
				return false
			}
			if len(trailing) != 0 {
				err = fmt.Errorf("trailing bytes found")
				return false
			}
			decodedForm = &rv
			err = nil
			return false
		}
		return true
	})
	//probably need two layers so that verifiers can read the dot without knowing
	//the PSK. The extra key (ephemeral just for this dot) should be returned
	//in the extra
	panic("need to do PSK extra")
	return
}
func (psk *PSKBodyScheme) EncryptBody(ctx context.Context, ec BodyEncryptionContext, intermediateForm *serdes.WaveAttestation) (encryptedForm *serdes.WaveAttestation, extra interface{}, err error) {
	pskec := ec.(PSKBodyEncryptionContext)
	encryptedForm = nil
	err = fmt.Errorf("no appropriate PSK found")
	pskec.GetEncryptPSK(ctx, intermediateForm, func(k EntitySecretKeySchemeInstance) bool {
		ct := serdes.PSKBodyCiphertext{}
		pub := k.Public()
		cf := pub.CanonicalForm()
		ct.EncryptedUnder = *cf
		der, serr := asn1.Marshal(intermediateForm)
		if serr != nil {
			err = serr
			return false
		}
		ciphertext, serr := pub.EncryptMessage(ctx, der)
		if serr != nil {
			err = serr
			return false
		}
		ct.AttestationBodyCiphetext = ciphertext
		rv := *intermediateForm
		rv.TBS.Body = asn1.NewExternal(ct)
		encryptedForm = &rv
		return false
		//ephemeralKey :=
		//ciphertext, err := k.EncryptMessageDH(ctx, to, content)
	})
	return
}
