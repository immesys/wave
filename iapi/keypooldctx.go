package iapi

import (
	"bytes"
	"context"
)

type KeyPoolDecryptionContext struct {
	attVerKey  []byte
	attProvKey []byte
	entz       []*Entity
	//These two go together
	entsecrets          []*EntitySecrets
	delegatedOnly       []bool
	domainVisibilityIds [][]byte
}

func NewKeyPoolDecryptionContext() *KeyPoolDecryptionContext {
	return &KeyPoolDecryptionContext{domainVisibilityIds: [][]byte{[]byte("$GLOBAL")}}
}

func (kpd *KeyPoolDecryptionContext) AddDomainVisibilityID(id []byte) {
	kpd.domainVisibilityIds = append(kpd.domainVisibilityIds, id)
}
func (kpd *KeyPoolDecryptionContext) AddEntitySecret(es *EntitySecrets, delegatedOnly bool) {
	kpd.entsecrets = append(kpd.entsecrets, es)
	kpd.delegatedOnly = append(kpd.delegatedOnly, delegatedOnly)
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

func (kpd *KeyPoolDecryptionContext) WR1EntityFromHash(ctx context.Context, hash HashSchemeInstance, loc LocationSchemeInstance) (*Entity, error) {
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
	return nil, nil
}
func (kpd *KeyPoolDecryptionContext) WR1OAQUEKeysForContent(ctx context.Context, dst HashSchemeInstance, slots [][]byte, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	for _, es := range kpd.entsecrets {
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
	return nil
}
func (kpd *KeyPoolDecryptionContext) WR1IBEKeysForPartitionLabel(ctx context.Context, dst HashSchemeInstance, onResult func(k EntitySecretKeySchemeInstance) bool) error {
	for _, es := range kpd.entsecrets {
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
