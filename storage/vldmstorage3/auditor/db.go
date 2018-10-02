package main

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/pem"
	"time"

	"github.com/dgraph-io/badger"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"

	spb "github.com/google/trillian/crypto/sigpb"
	_ "github.com/google/trillian/merkle/rfc6962"
)

const OurPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEmTz0jNtdPnob3U8uylM5PORUJPw2
9VEU8V68V8FtlxFxuuU6MFHzN5/3XnWCeJ0xJ1Uabk1r/eS0H7aWOksMNA==
-----END PUBLIC KEY-----`

const OurPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaK0u/I9YXTE7Yxb6
uGK3vX/KzWQVqCpqctv4hhAWEcuhRANCAASZPPSM210+ehvdTy7KUzk85FQk/Db1
URTxXrxXwW2XEXG65TowUfM3n/dedYJ4nTEnVRpuTWv95LQftpY6Sww0
-----END PRIVATE KEY-----`

func mustMarshalAny(pb proto.Message) *any.Any {
	value, err := ptypes.MarshalAny(pb)
	if err != nil {
		panic(err)
	}
	return value
}

func (a *adt) initmap() int64 {
	ctx := context.Background()
	pubk, _ := pem.Decode([]byte(OurPublicKey))
	privk, _ := pem.Decode([]byte(OurPrivateKey))
	var err error
	MapTree := &trillian.Tree{
		TreeState:          trillian.TreeState_ACTIVE,
		TreeType:           trillian.TreeType_MAP,
		HashStrategy:       trillian.HashStrategy_TEST_MAP_HASHER,
		HashAlgorithm:      spb.DigitallySigned_SHA256,
		SignatureAlgorithm: spb.DigitallySigned_ECDSA,
		DisplayName:        "WAVE Storage map",
		Description:        "Storage of attestations and entities for WAVE",
		PrivateKey: mustMarshalAny(&keyspb.PrivateKey{
			Der: privk.Bytes,
		}),
		PublicKey: &keyspb.PublicKey{
			Der: pubk.Bytes,
		},
		MaxRootDuration: ptypes.DurationProto(0 * time.Millisecond),
	}
	respct, err := a.adminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: MapTree,
	})
	if err != nil {
		panic(err)
	}
	_, err = a.mapClient.InitMap(ctx, &trillian.InitMapRequest{
		MapId: respct.TreeId,
	})
	if err != nil {
		panic(err)
	}
	return respct.TreeId
}

func (a *adt) LoadStateFromDB() {
	err := a.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte("state"))
		var st *state
		if err == badger.ErrKeyNotFound {
			st = a.defaultstate()
		} else {
			val, err := item.Value()
			if err != nil {
				return err
			}
			st = &state{}
			buf := bytes.NewBuffer(val)
			err = gob.NewDecoder(buf).Decode(st)
			if err != nil {
				return err
			}
		}
		a.state = st
		return nil
	})
	if err != nil {
		panic(err)
	}
}

func (a *adt) defaultstate() *state {
	treeid := a.initmap()
	return &state{
		MapTreeId:    treeid,
		OpLogIndex:   0,
		RootLogIndex: 0,
	}
}

func (a *adt) SaveStateToDB() {
	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(a.state)
	if err != nil {
		panic(err)
	}
	err = a.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("state"), buf.Bytes())
	})
	if err != nil {
		panic(err)
	}
}
