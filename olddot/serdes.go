package dot

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"math/big"

	"vuvuzela.io/crypto/bn256"

	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/immesys/wave/dot/objs"
	"github.com/immesys/wave/entity"
	"github.com/immesys/wave/params"
)

type DOT = objs.DOT

type EncryptionContext interface {
	SourceEntity() *entity.Entity
	DestEntity() *entity.Entity
	Auditors() [][]byte
}

const AESKeyholeSize = 16 + 12
const OAQUEMetaSlotPartitionLabel = "partitionLabel"
const OAQUEMetaSlotPartition = "partition"
const OAQUEMetaSlotResource = "resource"

//Some DOTS do not have a namespace. If it does, return it
//otherwise return "",false
// func dotNamespace(dot objs.DOT) ([]byte, error) {
// 	idx := strings.Index(dot.Content.URI, "/")
// 	if idx < 0 {
// 		fmt.Printf("no slash found\n")
// 		return nil, nil
// 	}
// 	fmt.Printf("thingy is %q", dot.Content.URI[:idx])
// 	ns, err := wavecrypto.UnFmtKey(dot.Content.URI[:idx])
// 	if err != nil {
// 		fmt.Printf("unfmt error: %v\n", err)
// 		return nil, err
// 	}
// 	return ns, nil
// }

func slotsToAttrMap(id [][]byte) oaque.AttributeList {
	rv := make(map[oaque.AttributeIndex]*big.Int)
	for index, arr := range id {
		if len(arr) > 0 {
			digest := sha256.Sum256(arr)
			bigint := new(big.Int).SetBytes(digest[:])
			bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
			bigint.Add(bigint, big.NewInt(1))
			rv[oaque.AttributeIndex(index)] = bigint
		}
	}
	return rv
}

//
// func idToAttrMap(id string) oaque.AttributeList {
// 	rv := make(map[oaque.AttributeIndex]*big.Int)
// 	parts := strings.Split(id, "/")
// 	index := oaque.AttributeIndex(0)
// 	for _, p := range parts {
// 		digest := sha256.Sum256([]byte(p))
// 		bigint := new(big.Int).SetBytes(digest[:])
// 		bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
// 		bigint.Add(bigint, big.NewInt(1))
// 		rv[index] = bigint
// 		index++
// 	}
// 	return rv
// }

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

func partitionkey(ns []byte) [][]byte {
	if len(ns) != 32 {
		panic("expected 32 byte namespace")
	}
	return [][]byte{[]byte(OAQUEMetaSlotPartitionLabel), ns}
}
func globalpartitionkey() [][]byte {
	return [][]byte{[]byte(OAQUEMetaSlotPartitionLabel), []byte("_all")}
}

// func makeDelegationSlots(s string) map[int]string {
// 	rv := make(map[int]string)
// 	rv[0] = OAQUEMetaSlotPartition
// 	parts := strings.Split(s, "/")
// 	for i, p := range parts {
// 		rv[i+1] = p
// 	}
// 	//TODO enforce max elements etc
// 	return rv
// }

func EncryptDOT(dot objs.DOT, ectx EncryptionContext) ([]byte, error) {
	//Generate ephemeral keys for signing
	signingEntity := entity.NewPartialEntity(true, false)

	//Set the outer signing key vk
	dot.Content.SigningVK = objs.Ed25519VK(signingEntity.VK)
	dot.PlaintextHeader.SigVK = objs.Ed25519VK(signingEntity.VK)
	//Perform the inner signature
	msgpackDotContents, err := dot.Content.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	dot.Content.Signature, err = ectx.SourceEntity().Ed25519Sign(msgpackDotContents)
	if err != nil {
		return nil, err
	}

	//Encrypt the partition label (the ID used to encrypt content and inheritance)
	//This is encrypted under OAQUE[DSTVK](partition, <namespace>) if a namespace is present
	//otherwise OAQUE[DSTVK](partition, "*")
	ns := dot.Content.NS
	dstparams := ectx.DestEntity().Params
	//The ID to encrypt the partition label with
	var idForPartition [][]byte
	if ns != nil {
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
	partLabelGroupElCiphertext, err := oaque.Encrypt(nil, dstparams, slotsToAttrMap(idForPartition), partLabelGroupEl)
	if err != nil {
		return nil, err
	}
	partLabelGroupElCiphertextBlob := partLabelGroupElCiphertext.Marshal()
	dot.EncryptedPartitionLabelKey = partLabelGroupElCiphertextBlob
	fmt.Printf("encrypting part %q using key %x nonce %x\n", dot.PartitionLabel, partLabelAESK, partLabelNonce)
	encodedPartitionLabel, err := objs.PartitionLabel(dot.PartitionLabel).MarshalMsg(nil)
	dot.EncryptedPartitionLabel = aesGCMEncrypt(partLabelAESK, encodedPartitionLabel, partLabelNonce)
	//The "partlabel" is a bit like a nonce but doesn't really have to be unique
	//because the SK is unique per message. It just needs to be unique across
	//the ECDH's within a single DOT
	ecdhSecret, err := signingEntity.Curve25519ECDH(ectx.DestEntity().VK, []byte("partlabel"), 16+12)
	if err != nil {
		return nil, err
	}
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
	sharedGroupElCiphertext, err := oaque.Encrypt(nil, dstparams, slotsToAttrMap(dot.PartitionLabel), sharedGroupEl)
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
	dot.Outersig, err = signingEntity.Ed25519Sign(serialized)
	if err != nil {
		return nil, err
	}
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
	EntityFromHash(ctx context.Context, hash []byte) (*entity.Entity, error)
	//OurOAQUEKey(vk []byte) oaque.MasterKey
	//OurSK(vk []byte) []byte

	//OAQUEParamsForVK(ctx context.Context, vk []byte) (*oaque.Params, error)
	//We call onResult for each result and if it returns true we keep searching for results. If there
	//is some kind of error, we stop calling onResult and return that error
	OAQUEKeysForContent(ctx context.Context, dst []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error
	OAQUEKeysForPartitionLabel(ctx context.Context, dst []byte, slots [][]byte, onResult func(k *oaque.PrivateKey) bool) error
	//OAQUEPartitionKeysFor(ctx context.Context, vk []byte) ([]*oaque.PrivateKey, error)
	//OAQUEDelegationKeyFor(ctx context.Context, vk []byte, partition string) (*oaque.PrivateKey, error)
}

func tryDecryptPartitionWithMaster(dt *objs.DOT, id [][]byte, p *oaque.Params, mk *oaque.MasterKey) ([][]byte, bool) {
	attrMap := slotsToAttrMap(id)
	privkey, err := oaque.KeyGen(nil, p, mk, attrMap)
	if err != nil {
		panic(err)
	}
	return tryDecryptPartitionWithKey(dt, p, privkey)
}
func tryDecryptPartitionWithKey(dt *objs.DOT, p *oaque.Params, pk *oaque.PrivateKey) ([][]byte, bool) {
	ciphertext := oaque.Ciphertext{}
	okay := ciphertext.Unmarshal(dt.EncryptedPartitionLabelKey)
	if !okay {
		return nil, false
	}
	groupEl := oaque.Decrypt(pk, &ciphertext)
	pool := cryptutils.GTToSecretKey(groupEl, make([]byte, 16+12))
	partitionAESK := pool[:16]
	partitionNonce := pool[16:]
	fmt.Printf("decrypting part using key %x nonce %x\n", partitionAESK, partitionNonce)
	encodedPartition, decryptOk := aesGCMDecrypt(partitionAESK, dt.EncryptedPartitionLabel, partitionNonce)
	if !decryptOk {
		return nil, false
	}
	partition := objs.PartitionLabel{}
	lo, err := partition.UnmarshalMsg(encodedPartition)
	if len(lo) != 0 || err != nil || len(partition) != params.OAQUESlots {
		return nil, false
	}
	return partition, true
}

type DecryptionResult struct {
	DOT  *DOT
	Hash []byte
	//If displaying some kind of message, this could be it
	Msg string
	//If true, the DOT is malicious and should be ignored
	BadOrMalformed bool
	//If true, the DOT is fully decrypted
	FullyDecrypted bool
	//If true, we know the partition label, but could not decrypt
	//the contents
	PartitionDecrypted bool
}

//Note that a bad or malformed response here is not an indication that the dot
//is bad, it might be that the AESK is wrong. Don't kill the dot
func DecryptDOTWithAESK(ctx context.Context, blob []byte, AESK []byte, dctx DecryptionContext) (*DecryptionResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	ures, err := UnpackDOT(ctx, blob)
	if err != nil {
		return nil, err
	}
	if ures.BadOrMalformed {
		return ures, nil
	}
	dot := ures.DOT
	aesk := AESK[:16]
	nonce := AESK[16:]
	dcontent, msg, err := decryptContent(dot.EncryptedContent, aesk, nonce)
	if err != nil {
		return nil, err
	}
	if dcontent == nil {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            msg,
		}, nil
	}
	dot.Content = dcontent
	src, err := dctx.EntityFromHash(ctx, dot.Content.SRC)
	if err != nil || src == nil {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not resolve src entity",
		}, nil
	}
	dst, err := dctx.EntityFromHash(ctx, dot.Content.DST)
	if err != nil || dst == nil {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not resolve dst entity",
		}, nil
	}
	dot.SRC = src
	dot.DST = dst
	return &DecryptionResult{
		DOT:            dot,
		FullyDecrypted: true,
	}, nil
}

func UnpackDOT(ctx context.Context, blob []byte) (*DecryptionResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	edot := &objs.ExternalDOT{}
	dotHash := sha3.NewKeccak256()
	dotHash.Write(blob)
	hash := dotHash.Sum(nil)
	remainder, err := edot.UnmarshalMsg(blob)
	if err != nil {
		return &DecryptionResult{
			BadOrMalformed: true,
			Hash:           hash,
			Msg:            fmt.Sprintf("Failed to unmarshal DOT: %v", err),
		}, nil
	}
	if len(remainder) != 0 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Hash:           hash,
			Msg:            fmt.Sprintf("Failed to unmarshal DOT: leftover bytes", err),
		}, nil
	}

	dot := edot.Internal()
	dot.Hash = hash
	dot.OriginalEncoding = blob

	//Sanitize DOT
	//PlaintextHeader
	if dot.PlaintextHeader == nil || len(dot.PlaintextHeader.DST) != 32 || len(dot.PlaintextHeader.SigVK) != 32 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Hash:           dot.Hash,
			Msg:            fmt.Sprintf("PlaintextHeader malformed"),
		}, nil
	}
	return &DecryptionResult{
		DOT:  dot,
		Hash: dot.Hash,
	}, nil
}
func decryptContent(ciphertext []byte, aesk []byte, nonce []byte) (*objs.DOTContent, string, error) {
	contentMsgPack, ok := aesGCMDecrypt(aesk, ciphertext, nonce)
	if !ok {
		return nil, "could not decrypt dot with correct key", nil
	}
	dcontent := &objs.DOTContent{}
	extra, err := dcontent.UnmarshalMsg(contentMsgPack)
	if err != nil || len(extra) != 0 {
		return nil, "could not unmarshal DOT content", nil
	}
	return dcontent, "", nil
}
func DecryptLabel(ctx context.Context, dot *DOT, dctx DecryptionContext) (*DecryptionResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	dst, err := dctx.EntityFromHash(ctx, dot.PlaintextHeader.DST)
	//If the error is not nil, something bad happened
	if err != nil {
		return nil, err
	}
	//If the dst is nil, it means we could not resolve the entity
	//we treat this as not being able to decrypt the dot
	if dst == nil {
		return &DecryptionResult{
			PartitionDecrypted: false,
			DOT:                dot,
			Msg:                "failed to resolve DST entity",
		}, nil
	}
	dot.DST = dst

	//TODO sanitize the rest of the dot
	masterkey := dst.MasterKey
	oaqueParamsForVK := dst.Params
	if oaqueParamsForVK == nil {
		return nil, fmt.Errorf("expected non-nil oaque params")
	}
	foundLabel := false
	if masterkey != nil {
		//This DOT is to one of our entities because we have the master key
		ecdhSecret, err := dst.Curve25519ECDH(dot.PlaintextHeader.SigVK, []byte("partlabel"), 16+12)
		if err != nil {
			return nil, err
		}
		directAESK := ecdhSecret[:16]
		directNonce := ecdhSecret[16:]
		partLabelPool, ok := aesGCMDecrypt(directAESK, dot.EncryptedDirectPartLabelKey, directNonce)
		if !ok {
			//the ECDH derived secret for the direct partition label was incorrect.
			//this should not happen, so the dot must be malicious
			return &DecryptionResult{
				BadOrMalformed: true,
				Msg:            fmt.Sprintf("Failed to get ECDH secret for direct partition label"),
			}, nil
		}
		partLabelAESK := partLabelPool[:16]
		partLabelNonce := partLabelPool[16:]
		encodedPartition, ok := aesGCMDecrypt(partLabelAESK, dot.EncryptedPartitionLabel, partLabelNonce)
		if !ok {
			return &DecryptionResult{
				BadOrMalformed: true,
				Msg:            fmt.Sprintf("DOT granter lied about part label direct key"),
			}, nil
		}
		partition := objs.PartitionLabel{}
		lo, err := partition.UnmarshalMsg(encodedPartition)
		if len(lo) != 0 || err != nil || len(partition) != params.OAQUESlots {
			return &DecryptionResult{
				BadOrMalformed: true,
				Msg:            fmt.Sprintf("Bad partition label format"),
			}, nil
		}
		dot.PartitionLabel = partition
		foundLabel = true
	} else {
		//Try all the private keys we have for this VK. There is no heirarchy
		//so no point extending keys. Be super mindful of the fact that we
		//try ALL the keys the decryption context gives us. In Engine the
		//dctx is constructed to only give us keys we have not tried before
		//but the interface doesn't enforce that.
		partitionslots := make([][]byte, params.OAQUESlots)
		partitionslots[0] = []byte(OAQUEMetaSlotPartitionLabel)
		allprivatekeys := []*oaque.PrivateKey{}
		err := dctx.OAQUEKeysForPartitionLabel(ctx, dst.VK, partitionslots, func(k *oaque.PrivateKey) bool {
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
		return &DecryptionResult{
			PartitionDecrypted: false,
			DOT:                dot,
			Hash:               dot.Hash,
			Msg:                "failed to decrypt partition label",
		}, nil
	}

	//Check the partition label is okay
	if len(dot.PartitionLabel) != params.OAQUESlots {
		return &DecryptionResult{
			BadOrMalformed: true,
			Hash:           dot.Hash,
			Msg:            fmt.Sprintf("bad number of partition slots"),
		}, nil
	}

	return &DecryptionResult{
		PartitionDecrypted: true,
		DOT:                dot,
		Hash:               dot.Hash,
		Msg:                "",
	}, nil

}
func DecryptContent(ctx context.Context, dot *DOT, dctx DecryptionContext) (*DecryptionResult, error) {

	//TODO sanitize the rest of the dot
	masterkey := dot.DST.MasterKey
	oaqueParamsForVK := dot.DST.Params
	if oaqueParamsForVK == nil {
		return nil, fmt.Errorf("expected non-nil oaque params")
	}
	var sharedPrivateKey *oaque.PrivateKey
	var err error
	if masterkey != nil {
		//Just generate it ourselves
		attrMap := slotsToAttrMap(dot.PartitionLabel)
		sharedPrivateKey, err = oaque.KeyGen(nil, oaqueParamsForVK, masterkey, attrMap)
		if err != nil {
			//This is an error because it should not happen
			return nil, fmt.Errorf("Could not generate content key: %v", err)
		}
	} else {
		//We need to get this from our pool of keys
		var sharedPrivateKey *oaque.PrivateKey
		err = dctx.OAQUEKeysForContent(ctx, dot.DST.Hash, dot.PartitionLabel, func(k *oaque.PrivateKey) bool {
			sharedPrivateKey = k
			return false
		})
		if err != nil {
			return nil, err
		}
		if sharedPrivateKey == nil {
			return &DecryptionResult{
				PartitionDecrypted: true,
				FullyDecrypted:     false,
				DOT:                dot,
				Msg:                "failed to decrypt content",
			}, nil
		}
	}
	ciphertext := oaque.Ciphertext{}
	ok := ciphertext.Unmarshal(dot.DelegationKeyhole)
	if !ok {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not unmarshal delegation key ciphertext",
		}, nil
	}
	sharedGroupEl := oaque.Decrypt(sharedPrivateKey, &ciphertext)
	sharedPool := cryptutils.GTToSecretKey(sharedGroupEl, make([]byte, 16+16+12+12))
	contentAESK := sharedPool[0:16]
	inheritanceAESK := sharedPool[16:32]
	contentNonce := sharedPool[32:44]
	inheritanceNonce := sharedPool[44:56]
	dcontent, msg, err := decryptContent(dot.EncryptedContent, contentAESK, contentNonce)
	if err != nil {
		return nil, err
	}
	if dcontent == nil {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            msg,
		}, nil
	}

	inheritanceMsgPack, ok := aesGCMDecrypt(inheritanceAESK, dot.EncryptedInheritance, inheritanceNonce)
	if !ok {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not decrypt inheritance with matching key",
		}, nil
	}

	dot.Content = dcontent
	//This must be sent along with the proof
	dot.AESContentKeyhole = make([]byte, 0, AESKeyholeSize)
	dot.AESContentKeyhole = append(dot.AESContentKeyhole, contentAESK...)
	dot.AESContentKeyhole = append(dot.AESContentKeyhole, contentNonce...)
	dinheritance := objs.InheritanceMap{}
	extra, err := dinheritance.UnmarshalMsg(inheritanceMsgPack)
	if err != nil || len(extra) != 0 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "DOT inheritance is invalid",
		}, nil
	}

	//TODO validation ,eg src==dst must fail some permissions etc etc
	return &DecryptionResult{
		FullyDecrypted:     true,
		PartitionDecrypted: true,
		DOT:                dot,
		Msg:                "success",
	}, nil
}

//We can either
//- succeed in decryting dot (never need to decrypt again)
//- fail to decrypt:
//  - dot is invalid (never need to look again)
//  - missing a key (look again whenever we get another dot from DST)
//  -
func DecryptFullDOT(ctx context.Context, blob []byte, dctx DecryptionContext) (*DecryptionResult, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	//PART ONE unpacking
	dot := &objs.DOT{}
	dotHash := sha3.NewKeccak256()
	dotHash.Write(blob)
	dot.Hash = dotHash.Sum(nil)
	remainder, err := dot.UnmarshalMsg(blob)
	if err != nil {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            fmt.Sprintf("Failed to unmarshal DOT: %v", err),
		}, nil
	}
	if len(remainder) != 0 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            fmt.Sprintf("Failed to unmarshal DOT: leftover bytes", err),
		}, nil
	}
	//Sanitize DOT
	//PlaintextHeader
	if dot.PlaintextHeader == nil || len(dot.PlaintextHeader.DST) != 32 || len(dot.PlaintextHeader.SigVK) != 32 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            fmt.Sprintf("PlaintextHeader malformed"),
		}, nil
	}
	//PART TWO labelling
	dst, err := dctx.EntityFromHash(ctx, dot.PlaintextHeader.DST)
	//If the error is not nil, something bad happened
	if err != nil {
		return nil, err
	}
	//If the dst is nil, it means we could not resolve the entity
	//we treat this as not being able to decrypt the dot
	if dst == nil {
		return &DecryptionResult{
			PartitionDecrypted: false,
			DOT:                dot,
			Msg:                "failed to resolve DST entity",
		}, nil
	}

	//TODO sanitize the rest of the dot
	masterkey := dst.MasterKey
	oaqueParamsForDst := dst.Params
	if oaqueParamsForDst == nil {
		return nil, fmt.Errorf("expected non-nil oaque params")
	}
	foundLabel := false
	if masterkey != nil {
		//This DOT is to one of our entities because we have the master key
		ecdhSecret, err := dst.Curve25519ECDH(dot.PlaintextHeader.SigVK, []byte("partlabel"), 16+12)
		if err != nil {
			return nil, err
		}
		directAESK := ecdhSecret[:16]
		directNonce := ecdhSecret[16:]
		partLabelPool, ok := aesGCMDecrypt(directAESK, dot.EncryptedDirectPartLabelKey, directNonce)
		if !ok {
			//the ECDH derived secret for the direct partition label was incorrect.
			//this should not happen, so the dot must be malicious
			return &DecryptionResult{
				BadOrMalformed: true,
				Msg:            fmt.Sprintf("Failed to get ECDH secret for direct partition label"),
			}, nil
		}
		partLabelAESK := partLabelPool[:16]
		partLabelNonce := partLabelPool[16:]
		encodedPartition, ok := aesGCMDecrypt(partLabelAESK, dot.EncryptedPartitionLabel, partLabelNonce)
		if !ok {
			return &DecryptionResult{
				BadOrMalformed: true,
				Msg:            fmt.Sprintf("DOT granter lied about part label direct key"),
			}, nil
		}
		partition := objs.PartitionLabel{}
		lo, err := partition.UnmarshalMsg(encodedPartition)
		if len(lo) != 0 || err != nil || len(partition) != params.OAQUESlots {
			return &DecryptionResult{
				BadOrMalformed: true,
				Msg:            fmt.Sprintf("Bad partition label format"),
			}, nil
		}
		dot.PartitionLabel = partition
		foundLabel = true
	} else {
		//Try all the private keys we have for this VK. There is no heirarchy
		//so no point extending keys
		partitionslots := make([][]byte, params.OAQUESlots)
		partitionslots[0] = []byte(OAQUEMetaSlotPartitionLabel)
		allprivatekeys := []*oaque.PrivateKey{}
		err := dctx.OAQUEKeysForPartitionLabel(ctx, dst.Hash, partitionslots, func(k *oaque.PrivateKey) bool {
			allprivatekeys = append(allprivatekeys, k)
			return true
		})
		if err != nil {
			return nil, err
		}
		//TODO we could maybe just try the keys inside the callback above rather
		for _, pk := range allprivatekeys {
			partition, ok := tryDecryptPartitionWithKey(dot, oaqueParamsForDst, pk)
			if ok {
				dot.PartitionLabel = partition
				foundLabel = true
				break
			}
		}
	}
	if !foundLabel {
		return &DecryptionResult{
			PartitionDecrypted: false,
			DOT:                dot,
			Msg:                "failed to decrypt partition label",
		}, nil
	}

	//Check the partition label is okay
	if len(dot.PartitionLabel) != params.OAQUESlots {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            fmt.Sprintf("bad number of partition slots"),
		}, nil
	}

	// PART THREE content
	//Ok now we have the partition label, lets try decode the content using that label
	var sharedPrivateKey *oaque.PrivateKey
	if masterkey != nil {
		//Just generate it ourselves
		attrMap := slotsToAttrMap(dot.PartitionLabel)
		sharedPrivateKey, err = oaque.KeyGen(nil, oaqueParamsForDst, masterkey, attrMap)
		if err != nil {
			//This is an error because it should not happen
			return nil, fmt.Errorf("Could not generate content key: %v", err)
		}
	} else {
		//We need to get this from our pool of keys
		var sharedPrivateKey *oaque.PrivateKey
		err = dctx.OAQUEKeysForContent(ctx, dst.Hash, dot.PartitionLabel, func(k *oaque.PrivateKey) bool {
			sharedPrivateKey = k
			return false
		})
		if err != nil {
			return nil, err
		}
		if sharedPrivateKey == nil {
			return &DecryptionResult{
				PartitionDecrypted: true,
				FullyDecrypted:     false,
				DOT:                dot,
				Msg:                "failed to decrypt content",
			}, nil
		}
	}
	ciphertext := oaque.Ciphertext{}
	ok := ciphertext.Unmarshal(dot.DelegationKeyhole)
	if !ok {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not unmarshal delegation key ciphertext",
		}, nil
	}
	sharedGroupEl := oaque.Decrypt(sharedPrivateKey, &ciphertext)
	sharedPool := cryptutils.GTToSecretKey(sharedGroupEl, make([]byte, 16+16+12+12))
	contentAESK := sharedPool[0:16]
	inheritanceAESK := sharedPool[16:32]
	contentNonce := sharedPool[32:44]
	inheritanceNonce := sharedPool[44:56]
	contentMsgPack, ok := aesGCMDecrypt(contentAESK, dot.EncryptedContent, contentNonce)
	if !ok {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not decrypt content with matching key",
		}, nil
	}
	inheritanceMsgPack, ok := aesGCMDecrypt(inheritanceAESK, dot.EncryptedInheritance, inheritanceNonce)
	if !ok {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not decrypt inheritance with matching key",
		}, nil
	}

	dcontent := objs.DOTContent{}
	extra, err := dcontent.UnmarshalMsg(contentMsgPack)
	if err != nil || len(extra) != 0 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "could not unmarshal DOT content",
		}, nil
	}
	dot.Content = &dcontent
	dinheritance := objs.InheritanceMap{}
	extra, err = dinheritance.UnmarshalMsg(inheritanceMsgPack)
	if err != nil || len(extra) != 0 {
		return &DecryptionResult{
			BadOrMalformed: true,
			Msg:            "DOT inheritance is invalid",
		}, nil
	}

	//TODO validation ,eg src==dst must fail some permissions etc etc
	return &DecryptionResult{
		FullyDecrypted:     true,
		PartitionDecrypted: true,
		DOT:                dot,
		Msg:                "success",
	}, nil
}
