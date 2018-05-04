package simplehttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keyspb"
	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/maphasher"
	"github.com/immesys/wave/iapi"
	"golang.org/x/crypto/sha3"
)

var _ iapi.StorageDriverInterface = &SimpleHTTPStorage{}

type MergePromise struct {
	TBS  []byte
	SigR *big.Int
	SigS *big.Int
}
type MergePromiseTBS struct {
	Key     []byte
	ValHash []byte
	MergeBy int64
}
type PutObjectRequest struct {
	DER []byte `json:"der"`
}
type PutObjectResponse struct {
	Hash           []byte        `json:"hash"`
	V1MergePromise *MergePromise `json:"v1promise"`
}
type InfoResponse struct {
	HashScheme string `json:"hashScheme"`
	Version    string `json:"version"`
}
type ObjectResponse struct {
	DER            []byte        `json:"der"`
	V1SMR          []byte        `json:"v1smr"`
	V1MapInclusion []byte        `json:"v1inclusion"`
	V1MergePromise *MergePromise `json:"v1promise"`
}
type NoSuchObjectResponse struct {
}
type IterateQueueResponse struct {
	Hash           []byte `json:"hash"`
	NextToken      string `json:"nextToken"`
	V1MergePromise *MergePromise
	V1SMR          []byte `json:"v1smr"`
	V1MapInclusion []byte `json:"v1inclusion"`
}
type EnqueueResponse struct {
	V1MergePromise *MergePromise `json:"v1promise"`
}
type NoSuchQueueEntryResponse struct {
}
type EnqueueRequest struct {
	EntryHash []byte `json:"entryHash"`
}

type SimpleHTTPStorage struct {
	url            string
	requireproof   bool
	publickey      string
	unpackedpubkey *ecdsa.PublicKey
	mapTree        *trillian.Tree
	mapVerifier    *client.MapVerifier
}

func (s *SimpleHTTPStorage) Location(context.Context) iapi.LocationSchemeInstance {
	//SimpleHTTP is version 1
	return iapi.NewLocationSchemeInstanceURL(s.url, 1)
}

func (s *SimpleHTTPStorage) PreferredHashScheme() iapi.HashScheme {
	//TODO
	return iapi.KECCAK256
}
func (s *SimpleHTTPStorage) Initialize(ctx context.Context, name string, config map[string]string) error {
	url, ok := config["url"]
	if !ok {
		return fmt.Errorf("the 'url' config option is mandatory")
	}
	s.url = url
	if config["v1key"] != "" {
		s.publickey = config["v1key"]
		s.requireproof = true
		s.initmap()
	}
	return nil
}

func (s *SimpleHTTPStorage) Status(ctx context.Context) (operational bool, info map[string]string, err error) {
	return true, make(map[string]string), nil
}

func (s *SimpleHTTPStorage) Put(ctx context.Context, content []byte) (iapi.HashSchemeInstance, error) {
	buf := bytes.Buffer{}
	putRequest := &PutObjectRequest{
		DER: content,
	}
	enc := json.NewEncoder(&buf)
	err := enc.Encode(putRequest)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(fmt.Sprintf("%s/obj", s.url), "application/json", &buf)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	rv := &PutObjectResponse{}
	err = json.Unmarshal(body, rv)
	if err != nil {
		return nil, err
	}
	//Lazily check that the hash is keccak256
	hi := iapi.HashSchemeInstanceFromMultihash(rv.Hash)
	if !hi.Supported() {
		return nil, fmt.Errorf("remote sent invalid hash")
	}
	expectedHash := iapi.KECCAK256.Instance(content)
	if s.requireproof {
		err := s.verifyV1Promise(rv.V1MergePromise, expectedHash.Value(), expectedHash.Value())
		if err != nil {
			return nil, err
		}
	}
	return hi, nil
}

func (s *SimpleHTTPStorage) verifyV1Promise(mp *MergePromise, expectedkey []byte, expectedcontent []byte) error {
	if s.unpackedpubkey == nil {
		der, trailing := pem.Decode([]byte(s.publickey))
		if len(trailing) != 0 {
			return fmt.Errorf("public key is invalid")
		}
		pub, err := x509.ParsePKIXPublicKey(der.Bytes)
		if err != nil {
			panic(err)
		}
		pubk := pub.(*ecdsa.PublicKey)
		s.unpackedpubkey = pubk
	}
	hash := sha3.Sum256(mp.TBS)
	if !ecdsa.Verify(s.unpackedpubkey, hash[:], mp.SigR, mp.SigS) {
		return fmt.Errorf("signature is invalid")
	}
	mptbs := &MergePromiseTBS{}
	err := json.Unmarshal(mp.TBS, &mptbs)
	if err != nil {
		return err
	}
	if expectedkey != nil && !bytes.Equal(mptbs.Key, expectedkey) {
		return fmt.Errorf("promise is for a different key")
	}
	if expectedcontent != nil && !bytes.Equal(mptbs.ValHash, expectedcontent) {
		return fmt.Errorf("promise is for different content")
	}
	return nil
}
func (s *SimpleHTTPStorage) Get(ctx context.Context, hash iapi.HashSchemeInstance) (content []byte, err error) {
	b64 := hash.MultihashString()
	resp, err := http.Get(fmt.Sprintf("%s/obj/%s", s.url, b64))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, iapi.ErrObjectNotFound
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	rv := &ObjectResponse{}
	err = json.Unmarshal(body, rv)
	if err != nil {
		return nil, err
	}
	if s.requireproof {
		if rv.V1MergePromise != nil {
			fmt.Printf("promise\n")
			err := s.verifyV1Promise(rv.V1MergePromise, hash.Value(), hash.Value())
			if err != nil {
				return nil, err
			}
		} else {
			fmt.Printf("inclusion\n")
			err := s.verifyV1smr(rv.V1SMR, rv.V1MapInclusion, hash.Value(), rv.DER)
			if err != nil {
				return nil, err
			}
		}
	}
	return rv.DER, nil
}

func (s *SimpleHTTPStorage) Enqueue(ctx context.Context, queueId iapi.HashSchemeInstance, object iapi.HashSchemeInstance) error {
	buf := bytes.Buffer{}
	queueRequest := &EnqueueRequest{
		EntryHash: object.Multihash(),
	}
	err := json.NewEncoder(&buf).Encode(queueRequest)
	if err != nil {
		panic(err)
	}
	b64 := queueId.MultihashString()
	resp, err := http.Post(fmt.Sprintf("%s/queue/%s", s.url, b64), "application/json", &buf)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	enqueueResp := &EnqueueResponse{}
	err = json.Unmarshal(body, enqueueResp)
	if err != nil {
		return fmt.Errorf("Remote sent invalid response")
	}
	if s.requireproof {
		err := s.verifyV1Promise(enqueueResp.V1MergePromise, nil, nil)
		if err != nil {
			return err
		}
	}
	if resp.StatusCode != 201 {
		return fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	return nil
}

func (s *SimpleHTTPStorage) IterateQueue(ctx context.Context, queueId iapi.HashSchemeInstance, iteratorToken string) (object iapi.HashSchemeInstance, nextToken string, err error) {
	b64 := queueId.MultihashString()
	resp, err := http.Get(fmt.Sprintf("%s/queue/%s?token=%s", s.url, b64, iteratorToken))
	if err != nil {
		return nil, "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, "", iapi.ErrNoMore
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	iterR := &IterateQueueResponse{}
	err = json.Unmarshal(body, iterR)
	if err != nil {
		return nil, "", fmt.Errorf("Remote sent invalid response")
	}
	hi := iapi.HashSchemeInstanceFromMultihash(iterR.Hash)
	if s.requireproof {
		expectedHashContents := make([]byte, 40)
		copy(expectedHashContents[:32], queueId.Value())
		if iteratorToken == "" {
			iteratorToken = "0"
		}
		index, err := strconv.ParseInt(iteratorToken, 10, 64)
		if err != nil {
			return nil, "", err
		}
		binary.LittleEndian.PutUint64(expectedHashContents[32:], uint64(index))
		expectedHash := iapi.KECCAK256.Instance(expectedHashContents)
		expectedVHash := iapi.KECCAK256.Instance(iterR.Hash)
		if iterR.V1MergePromise != nil {
			err := s.verifyV1Promise(iterR.V1MergePromise, expectedHash.Value(), expectedVHash.Value())
			if err != nil {
				return nil, "", err
			}
		} else {
			err := s.verifyV1smr(iterR.V1SMR, iterR.V1MapInclusion, expectedHash.Value(), iterR.Hash)
			if err != nil {
				return nil, "", err
			}
		}
	}
	return hi, iterR.NextToken, nil
}

func (s *SimpleHTTPStorage) verifyV1smr(smr []byte, inclusion []byte, key []byte, value []byte) error {

	pbinc := trillian.MapLeafInclusion{}
	err := proto.Unmarshal(inclusion, &pbinc)
	if err != nil {
		return fmt.Errorf("malformed proof")
	}
	pbsmr := trillian.SignedMapRoot{}
	err = proto.Unmarshal(smr, &pbsmr)
	if err != nil {
		return fmt.Errorf("malformed proof")
	}
	if key != nil && !bytes.Equal(pbinc.Leaf.Index, key) {
		return fmt.Errorf("malformed proof (wrong key)")
	}
	if value != nil && !bytes.Equal(pbinc.Leaf.LeafValue, value) {
		fmt.Printf("expected %x\n", value)
		fmt.Printf("received %x\n", pbinc.Leaf.LeafValue)
		return fmt.Errorf("malformed proof (wrong value)")
	}
	err = s.mapVerifier.VerifyMapLeafInclusion(&pbsmr, &pbinc)
	if err != nil {
		return fmt.Errorf("proof is invalid: %s", err)
	}
	return nil
}

func (s *SimpleHTTPStorage) initmap() {
	pubk, _ := pem.Decode([]byte(s.publickey))
	if pubk == nil {
		panic(fmt.Sprintf("bad public key %q", s.publickey))
	}
	s.mapTree = &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_TEST_MAP_HASHER,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "WAVE Storage map",
		Description:        "Storage of attestations and entities for WAVE",
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	var err error
	s.mapVerifier, err = client.NewMapVerifierFromTree(s.mapTree)
	if err != nil {
		panic(err)
	}

}
