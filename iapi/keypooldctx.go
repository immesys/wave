package iapi

import (
	"bytes"
	"context"
	"fmt"
)

type KeyPoolDecryptionContext struct {
	attVerKey           AttestationVerifierKeySchemeInstance
	entz                []*Entity
	entsecrets          []*EntitySecrets
	domainVisibilityIds [][]byte
}

func NewKeyPoolDecryptionContext() *KeyPoolDecryptionContext {
	return &KeyPoolDecryptionContext{}
}

func (kpd *KeyPoolDecryptionContext) AddEntitySecret(es *EntitySecrets) {
	kpd.entsecrets = append(kpd.entsecrets, es)
}
func (kpd *KeyPoolDecryptionContext) SetWR1VerifierBodyKey(atv AttestationVerifierKeySchemeInstance) {
	kpd.attVerKey = atv
}
func (kpd *KeyPoolDecryptionContext) WR1VerifierBodyKey(ctx context.Context) AttestationVerifierKeySchemeInstance {
	return kpd.attVerKey
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
	for _, es := range kpd.entsecrets {
		hi := es.Entity.Keccak256HI()
		fmt.Printf("comparison %s=%s %x=%x\n", dst.OID().String(), hi.OID().String(), dst.Value(), hi.Value())
		if dst.OID().Equal(hi.OID()) && bytes.Equal(hi.Value(), dst.Value()) {
			fmt.Printf("found entity\n")
			dek, err := es.WR1DirectDecryptionKey(ctx)
			if err != nil {
				panic(err)
			}
			more := onResult(dek)
			if !more {
				return nil
			}
		}
		fmt.Printf("entity hash did not match\n")
	}
	fmt.Printf("key pool: no direct keys\n")
	return nil
}
