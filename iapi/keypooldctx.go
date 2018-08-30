package iapi

import (
	"bytes"
	"context"

	"github.com/immesys/wave/wve"
)

type KeyPoolDecryptionContext struct {
	attVerKey  []byte
	attProvKey []byte
	entz       []*Entity
	//These two go together
	entsecrets          []*EntitySecrets
	labelOnly           []*EntitySecrets
	delegatedOnly       []bool
	domainVisibilityIds [][]byte
	underlyingContext   KeyPoolUnderlyingContext
}

type KeyPoolUnderlyingContext interface {
	EntityByHashLoc(ctx context.Context, h HashSchemeInstance, loc LocationSchemeInstance) (*Entity, wve.WVE)
	//	WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, slots [][]byte, onResult func(k SlottedSecretKey) bool) error
	//  WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error
}

var _ WR1BodyEncryptionContext = &KeyPoolDecryptionContext{}
var _ WR1DecryptionContext = &KeyPoolDecryptionContext{}

func NewKeyPoolDecryptionContext() *KeyPoolDecryptionContext {
	return &KeyPoolDecryptionContext{domainVisibilityIds: [][]byte{[]byte("$GLOBAL")}}
}

func (kpd *KeyPoolDecryptionContext) SetUnderlyingContext(ctx KeyPoolUnderlyingContext) {
	kpd.underlyingContext = ctx
}
func (kpd *KeyPoolDecryptionContext) AddDomainVisibilityID(id []byte) {
	kpd.domainVisibilityIds = append(kpd.domainVisibilityIds, id)
}
func (kpd *KeyPoolDecryptionContext) AddEntitySecret(es *EntitySecrets, delegatedOnly bool) {
	kpd.entsecrets = append(kpd.entsecrets, es)
	kpd.delegatedOnly = append(kpd.delegatedOnly, delegatedOnly)
}
func (kpd *KeyPoolDecryptionContext) AddEntitySecretsLabelOnly(es *EntitySecrets) {
	kpd.labelOnly = append(kpd.labelOnly, es)
}
func (kpd *KeyPoolDecryptionContext) AddEntity(e *Entity) {
	kpd.entz = append(kpd.entz, e)
}
func (kpd *KeyPoolDecryptionContext) WR1EntityFromHash(ctx context.Context, hash HashSchemeInstance, loc LocationSchemeInstance) (*Entity, error) {
	rv, err := kpd.EntityByHashLoc(ctx, hash, loc)
	if err != nil {
		return nil, err
	}
	if rv == nil && kpd.underlyingContext != nil {
		return kpd.underlyingContext.EntityByHashLoc(ctx, hash, loc)
	} else {
		return rv, err
	}
}
func (kpd *KeyPoolDecryptionContext) SetWR1VerifierBodyKey(atv []byte) {
	kpd.attVerKey = atv
}
func (kpd *KeyPoolDecryptionContext) WR1VerifierBodyKey(ctx context.Context) []byte {
	return kpd.attVerKey
}
func (kpd *KeyPoolDecryptionContext) SetWR1ProverBodyKey(atv []byte) {
	kpd.attProvKey = atv
}
func (kpd *KeyPoolDecryptionContext) WR1ProverBodyKey(ctx context.Context) []byte {
	return kpd.attProvKey
}
func (kpd *KeyPoolDecryptionContext) EntityByHashLoc(ctx context.Context, hash HashSchemeInstance, loc LocationSchemeInstance) (*Entity, wve.WVE) {
	//TODO support non-keccack schemes
	for _, e := range kpd.entz {
		hi := e.Keccak256HI()
		if hash.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), hash.Value()) {
			return e, nil
		}
	}
	for _, es := range kpd.entsecrets {
		hi := es.Entity.Keccak256HI()
		if hash.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), hash.Value()) {
			return es.Entity, nil
		}
	}
	for _, es := range kpd.labelOnly {
		hi := es.Entity.Keccak256HI()
		if hash.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), hash.Value()) {
			return es.Entity, nil
		}
	}
	if kpd.underlyingContext != nil {
		return kpd.underlyingContext.EntityByHashLoc(ctx, hash, loc)
	}
	return nil, nil
}
func (kpd *KeyPoolDecryptionContext) WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, slots [][]byte, onResult func(k SlottedSecretKey) bool) error {
	toproc := []*EntitySecrets{}
	toproc = append(toproc, kpd.entsecrets...)
	for _, es := range toproc {
		hi := es.Entity.Keccak256HI()
		if dst.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), dst.Value()) {
			bk, err := es.WR1BodyKey(ctx, slots)
			if err != nil {
				panic(err)
			}
			more := onResult(bk)
			if !more {
				return nil
			}
		}
	}
	// if kpd.underlyingContext != nil {
	// 	return kpd.underlyingContext.WR1OAQUEKeysForContent(ctx, dst, slots, onResult)
	// }
	return nil
}
func (kpd *KeyPoolDecryptionContext) WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	toproc := []*EntitySecrets{}
	toproc = append(toproc, kpd.labelOnly...)
	toproc = append(toproc, kpd.entsecrets...)
	for _, es := range toproc {
		hi := es.Entity.Keccak256HI()
		if dst.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), dst.Value()) {
			for _, dv := range kpd.domainVisibilityIds {
				dk, err := es.WR1LabelKey(ctx, dv)
				if err != nil {
					panic(err)
				}
				more := onResult(dk)
				if !more {
					return nil
				}
			}
		}
	}
	// if kpd.underlyingContext != nil {
	// 	return kpd.underlyingContext.WR1IBEKeysForPartitionLabel(ctx, dst, onResult)
	// }
	return nil
}
func (kpd *KeyPoolDecryptionContext) WR1AttesterDirectDecryptionKey(ctx context.Context, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	for idx, es := range kpd.entsecrets {
		if kpd.delegatedOnly[idx] {
			continue
		}
		dek, err := es.WR1DirectDecryptionKey(ctx)
		if err != nil {
			panic(err)
		}
		more := onResult(dek)
		if !more {
			return nil
		}
	}
	return nil
}
func (kpd *KeyPoolDecryptionContext) WR1DirectDecryptionKey(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	for idx, es := range kpd.entsecrets {
		if kpd.delegatedOnly[idx] {
			continue
		}
		hi := es.Entity.Keccak256HI()

		if dst.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), dst.Value()) {
			dek, err := es.WR1DirectDecryptionKey(ctx)
			if err != nil {
				panic(err)
			}
			more := onResult(dek)
			if !more {
				return nil
			}
		}
	}
	return nil
}
