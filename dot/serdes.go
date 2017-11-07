package dot

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"

	"vuvuzela.io/crypto/bn256"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/davecgh/go-spew/spew"
	wavecrypto "github.com/immesys/wave/crypto"
	"github.com/immesys/wave/dot/objs"
	"golang.org/x/crypto/sha3"
)

type EncryptionContext interface {
	SourceKeys() (sk []byte, vk []byte)
	DstOAQUEParams() *oaque.Params
	SrcOAQUEParams() (*oaque.Params, oaque.MasterKey)
	Auditors() [][]byte
}

const OAQUEMetaSlotPartitionLabel = "partitionLabel"
const OAQUEMetaSlotPartition = "partition"
const OAQUEMetaSlotResource = "resource"

//Some DOTS do not have a namespace. If it does, return it
//otherwise return "",false
func dotNamespace(dot objs.DOT) (string, bool) {
	idx := strings.Index(dot.Content.URI, "/")
	if idx < 0 {
		return "", false
	}
	return dot.Content.URI[:idx], true
}

func idToInts(id string) []*big.Int {
	rv := []*big.Int{}
	parts := strings.Split(id, "/")
	for _, p := range parts {
		digest := sha256.Sum256([]byte(p))
		bigint := new(big.Int).SetBytes(digest[:])
		bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
		bigint.Add(bigint, big.NewInt(1))
		rv = append(rv, bigint)
	}
	return rv
}
func idToAttrMap(id string) oaque.AttributeList {
	rv := make(map[oaque.AttributeIndex]*big.Int)
	parts := strings.Split(id, "/")
	index := oaque.AttributeIndex(0)
	for _, p := range parts {
		digest := sha256.Sum256([]byte(p))
		bigint := new(big.Int).SetBytes(digest[:])
		bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
		bigint.Add(bigint, big.NewInt(1))
		rv[index] = bigint
		index++
	}
	return rv
}

//It is important that the key is not reused for this function
func aesGCMEncrypt(key []byte, blob []byte, nonce []byte) []byte {
	if len(key) != 16 {
		panic("expected AES128 key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}
	ciphertext := aesgcm.Seal(nil, nonce, blob, nil)
	return ciphertext
}
func aesGCMDecrypt(key []byte, ciphertext []byte, nonce []byte) ([]byte, bool) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	aesgcm, err := cipher.NewGCMWithNonceSize(block, 12)
	if err != nil {
		panic(err.Error())
	}
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, false
	}
	return plaintext, true
}
func partitionkey(ns string) string {
	return OAQUEMetaSlotPartitionLabel + "/" + ns
}
func globalpartitionkey() string {
	return OAQUEMetaSlotPartitionLabel + "/*"
}
func makeDelegationSlots(s string) map[int]string {
	rv := make(map[int]string)
	rv[0] = OAQUEMetaSlotPartition
	parts := strings.Split(s, "/")
	for i, p := range parts {
		rv[i+1] = p
	}
	//TODO enforce max elements etc
	return rv
}
func randInt() *big.Int {
	rv, err := rand.Int(rand.Reader, bn256.Order)
	if err != nil {
		panic(err)
	}
	return rv
}
func generateECDHSecret(vk []byte, sk []byte, nonce []byte, dst []byte) []byte {
	fmt.Printf("ECDH SECRET GEN vk=%x sk=%x nonce=%x\n", vk, sk, nonce)
	secret := wavecrypto.Ed25519CalcSecret(sk, vk)
	shake := sha3.NewShake256()
	shake.Write(secret)
	shake.Write(nonce)
	shake.Read(dst)
	return dst
}
func EncryptDOT(dot objs.DOT, ectx EncryptionContext) ([]byte, error) {
	//Generate ephemeral keys for signing
	signingSK, signingVK := wavecrypto.GenerateKeypair()

	//Set the outer signing key vk
	dot.Content.SigningVK = objs.Ed25519VK([]byte(signingVK))
	dot.PlaintextHeader.SigVK = objs.Ed25519VK([]byte(signingVK))
	//Perform the inner signature
	sk, vk := ectx.SourceKeys()
	dot.Content.Signature = make([]byte, 64)
	msgpackDotContents, err := dot.Content.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	wavecrypto.SignBlob(sk, vk, dot.Content.Signature, msgpackDotContents)

	//Encrypt the partition label (the ID used to encrypt content and inheritance)
	//This is encrypted under OAQUE[DSTVK](partition, <namespace>) if a namespace is present
	//otherwise OAQUE[DSTVK](partition, "*")
	ns, hasNS := dotNamespace(dot)
	dstparams := ectx.DstOAQUEParams()
	//The ID to encrypt the partition label with
	var idForPartition string
	if hasNS {
		idForPartition = partitionkey(ns)
	} else {
		idForPartition = globalpartitionkey()
	}
	fmt.Printf("idForPartition was %v\n", idForPartition)
	//Generate a key we can use to encrypt
	partLabelPool, partLabelGroupEl := cryptutils.GenerateKey(make([]byte, 16+12))
	partLabelAESK := partLabelPool[:16]
	partLabelNonce := partLabelPool[16:]
	//Encrypt the group element
	partLabelGroupElCiphertext, err := oaque.Encrypt(nil, dstparams, idToAttrMap(idForPartition), partLabelGroupEl)
	if err != nil {
		return nil, err
	}
	partLabelGroupElCiphertextBlob := partLabelGroupElCiphertext.Marshal()
	dot.EncryptedPartitionLabelKey = partLabelGroupElCiphertextBlob
	fmt.Printf("encrypting part %q using key %x nonce %x\n", dot.PartitionLabel, partLabelAESK, partLabelNonce)
	dot.EncryptedPartitionLabel = aesGCMEncrypt(partLabelAESK, []byte(dot.PartitionLabel), partLabelNonce)
	//The "partlabel" is a bit like a nonce but doesn't really have to be unique
	//because the SK is unique per message. It just needs to be unique across
	//the ECDH's within a single DOT
	ecdhSecret := generateECDHSecret(dot.PlaintextHeader.DSTVK, signingSK, []byte("partlabel"), make([]byte, 16+12))
	directAESK := ecdhSecret[:16]
	directNonce := ecdhSecret[16:]
	//This allows the DST to decrypt DOTS without knowing what namespace they are on
	dot.EncryptedDirectPartLabelKey = aesGCMEncrypt(directAESK, partLabelPool, directNonce)

	//Encrypt the content and the inheritance
	//We use one HIBE operation to encrypt both, but the AESK keys are independant
	sharedPool, sharedGroupEl := cryptutils.GenerateKey(make([]byte, 16+16+12+12))
	contentAESK := sharedPool[0:16]
	inheritanceAESK := sharedPool[16:32]
	contentNonce := sharedPool[32:44]
	inheritanceNonce := sharedPool[44:56]
	sharedGroupElCiphertext, err := oaque.Encrypt(nil, dstparams, idToAttrMap(dot.PartitionLabel), sharedGroupEl)
	if err != nil {
		return nil, err
	}
	dot.DelegationKeyhole = sharedGroupElCiphertext.Marshal()
	//Last time the sig was zeroed out
	finalSerializedDotContents, err := dot.Content.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	serializedInheritance, err := dot.Inheritance.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	dot.EncryptedContent = aesGCMEncrypt(contentAESK, finalSerializedDotContents, contentNonce)
	dot.EncryptedInheritance = aesGCMEncrypt(inheritanceAESK, serializedInheritance, inheritanceNonce)

	//Zero out the outer signature
	dot.Outersig = make([]byte, 64)
	//Serialize the whole thing for signing
	serialized, err := dot.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("iser:(%03d) %x\n", len(serialized), serialized)
	wavecrypto.SignBlob(signingSK, signingVK, dot.Outersig, serialized)
	finalSerialization, err := dot.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	//fmt.Printf("fser:(%03d) %x\n", len(finalSerialization), finalSerialization)
	return finalSerialization, nil
}

// GTToSecretKey hashes an element in group GT to get a 32-byte secret key for
// for use with a secretbox.
func GTToSecretKey(gt *bn256.GT) [32]byte {
	shake := sha3.NewShake256()
	shake.Write(gt.Marshal())
	var sk [32]byte
	shake.Read(sk[:])
	return sk
}

type DecryptionContext interface {
	NamespaceHints() []string
	OurOAQUEKey(vk []byte) oaque.MasterKey
	OurSK(vk []byte) []byte

	OAQUEParamsForVK(ctx context.Context, vk []byte) (*oaque.Params, error)
	//We call onResult for each result and if it returns true we keep searching for results. If there
	//is some kind of error, we stop calling onResult and return that error
	OAQUEKeysFor(ctx context.Context, vk []byte, slots map[int]string, onResult func(k *oaque.PrivateKey) bool) error
	//OAQUEPartitionKeysFor(ctx context.Context, vk []byte) ([]*oaque.PrivateKey, error)
	//OAQUEDelegationKeyFor(ctx context.Context, vk []byte, partition string) (*oaque.PrivateKey, error)
}

func tryDecryptPartitionWithMaster(dt *objs.DOT, id string, p *oaque.Params, mk oaque.MasterKey) (string, bool) {
	attrMap := idToAttrMap(id)
	privkey, err := oaque.KeyGen(nil, p, mk, attrMap)
	if err != nil {
		panic(err)
	}
	return tryDecryptPartitionWithKey(dt, p, privkey)
}
func tryDecryptPartitionWithKey(dt *objs.DOT, p *oaque.Params, pk *oaque.PrivateKey) (string, bool) {
	ciphertext := oaque.Ciphertext{}
	_, okay := ciphertext.Unmarshal(dt.EncryptedPartitionLabelKey)
	if !okay {
		return "", false
	}
	groupEl := oaque.Decrypt(pk, &ciphertext)
	pool := cryptutils.GTToSecretKey(groupEl, make([]byte, 16+12))
	partitionAESK := pool[:16]
	partitionNonce := pool[16:]
	fmt.Printf("decrypting part using key %x nonce %x\n", partitionAESK, partitionNonce)
	partition, decryptOk := aesGCMDecrypt(partitionAESK, dt.EncryptedPartitionLabel, partitionNonce)
	fmt.Printf("decryption result %q / %v\n", partition, decryptOk)
	return string(partition), decryptOk
}

//We can either
//- succeed in decryting dot (never need to decrypt again)
//- fail to decrypt:
//  - dot is invalid (never need to look again)
//  - missing a key (look again whenever we get another dot from DST)
//  -
func DecryptDOT(ctx context.Context, blob []byte, dctx DecryptionContext) (*objs.DOT, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	//First, deserialize the top level
	dot := &objs.DOT{}
	remainder, err := dot.UnmarshalMsg(blob)
	if err != nil {
		return nil, fmt.Errorf("Failed to unmarshal DOT: %v", err)
	}
	if len(remainder) != 0 {
		return nil, fmt.Errorf("Failed to unmarshal DOT: leftover bytes")
	}
	spew.Dump(dot)
	fmt.Printf("deserialized top level. Dst VK is: %s\n", wavecrypto.FmtKey(dot.PlaintextHeader.DSTVK))
	//TODO sanitize DOT object (plaintext header not null, dstvk correct size etc etc)
	masterkey := dctx.OurOAQUEKey(dot.PlaintextHeader.DSTVK)
	oaqueParamsForVK, err := dctx.OAQUEParamsForVK(ctx, dot.PlaintextHeader.DSTVK)
	if err != nil {
		return nil, err
	}
	foundLabel := false
	if masterkey != nil {
		//This DOT is to one of our VKs
		ecdhSecret := generateECDHSecret(dot.PlaintextHeader.SigVK, dctx.OurSK(dot.PlaintextHeader.DSTVK), []byte("partlabel"), make([]byte, 16+12))
		directAESK := ecdhSecret[:16]
		directNonce := ecdhSecret[16:]
		partLabelPool, ok := aesGCMDecrypt(directAESK, dot.EncryptedDirectPartLabelKey, directNonce)
		if !ok {
			return nil, fmt.Errorf("Failed to get ECDH secret for direct partition label")
		}
		partLabelAESK := partLabelPool[:16]
		partLabelNonce := partLabelPool[16:]
		partition, ok := aesGCMDecrypt(partLabelAESK, dot.EncryptedPartitionLabel, partLabelNonce)
		if !ok {
			return nil, fmt.Errorf("DOT granter lied about part label direct key")
		}
		dot.PartitionLabel = string(partition)
		foundLabel = true
		/*
			    //This works, but we added the direct key field to make this easier
			    //Try the global key first
					gk := globalpartitionkey()
					partition, ok := tryDecryptPartitionWithMaster(dot, gk, hibeParamsForVK, masterkey)
					if ok {
						dot.PartitionLabel = partition
						foundLabel = true
					} else {
						fmt.Printf("trying namespace hints")
						//Generate all the namespace keys and try to decode the partition
						for _, ns := range dctx.NamespaceHints() {
							nsk := partitionkey(ns)
							partition, ok := tryDecryptPartitionWithMaster(dot, nsk, hibeParamsForVK, masterkey)
							if ok {
								dot.PartitionLabel = partition
								foundLabel = true
								break
							}
						}
					}*/
	} else {
		//Try all the private keys we have for this VK. There is no heirarchy
		//so no point extending keys
		partitionslots := make(map[int]string)
		partitionslots[0] = OAQUEMetaSlotPartitionLabel
		allprivatekeys := []*oaque.PrivateKey{}
		err := dctx.OAQUEKeysFor(ctx, dot.PlaintextHeader.DSTVK, partitionslots, func(k *oaque.PrivateKey) bool {
			allprivatekeys = append(allprivatekeys, k)
			return true
		})
		if err != nil {
			return nil, err
		}
		//TODO we could maybe just try the keys inside the callback above rather
		for _, pk := range allprivatekeys {
			partition, ok := tryDecryptPartitionWithKey(dot, oaqueParamsForVK, pk)
			if ok {
				dot.PartitionLabel = partition
				foundLabel = true
				break
			}
		}
	}
	if !foundLabel {
		//TODO maybe for DOTs granted directly to a VK, there is a key that can be better
		//predicted without knowing the namespace? This could use ECDH(SigningVK, DstVK)
		return nil, fmt.Errorf("Failed to decrypt partition label (maybe on an unknown namespace?)")
	}

	//Ok now we have the partition label, lets try decode the content using that label
	var sharedPrivateKey *oaque.PrivateKey
	if masterkey != nil {
		//Just generate it ourselves
		attrMap := idToAttrMap(dot.PartitionLabel)
		sharedPrivateKey, err = oaque.KeyGen(nil, oaqueParamsForVK, masterkey, attrMap)
		if err != nil {
			return nil, fmt.Errorf("Could not generate content key: %v", err)
		}
	} else {
		//We need to get this from our pool of keys
		delegationSlots := makeDelegationSlots(dot.PartitionLabel)
		var sharedPrivateKey *oaque.PrivateKey
		err = dctx.OAQUEKeysFor(ctx, dot.PlaintextHeader.DSTVK, delegationSlots, func(k *oaque.PrivateKey) bool {
			sharedPrivateKey = k
			return false
		})
		if err != nil {
			return nil, err
		}
		if sharedPrivateKey == nil {
			return nil, fmt.Errorf("We do not have the delegation key for this DOT")
		}
	}
	ciphertext := oaque.Ciphertext{}
	_, ok := ciphertext.Unmarshal(dot.DelegationKeyhole)
	if !ok {
		return nil, fmt.Errorf("Could not unmarshal delegation key ciphertext")
	}
	sharedGroupEl := oaque.Decrypt(sharedPrivateKey, &ciphertext)
	sharedPool := cryptutils.GTToSecretKey(sharedGroupEl, make([]byte, 16+16+12+12))
	contentAESK := sharedPool[0:16]
	inheritanceAESK := sharedPool[16:32]
	contentNonce := sharedPool[32:44]
	inheritanceNonce := sharedPool[44:56]
	contentMsgPack, ok := aesGCMDecrypt(contentAESK, dot.EncryptedContent, contentNonce)
	if !ok {
		return nil, fmt.Errorf("Could not decrypt content with master key (unusual)")
	}
	inheritanceMsgPack, ok := aesGCMDecrypt(inheritanceAESK, dot.EncryptedInheritance, inheritanceNonce)
	if !ok {
		return nil, fmt.Errorf("Could not decrypt inheritance with master key (unusual)")
	}

	dcontent := objs.DOTContent{}
	extra, err := dcontent.UnmarshalMsg(contentMsgPack)
	if err != nil || len(extra) != 0 {
		return nil, fmt.Errorf("DOT content is invalid")
	}
	dot.Content = &dcontent
	dinheritance := objs.InheritanceMap{}
	extra, err = dinheritance.UnmarshalMsg(inheritanceMsgPack)
	if err != nil || len(extra) != 0 {
		return nil, fmt.Errorf("DOT inheritance is invalid")
	}

	return dot, nil
}
