package iapi

import "encoding/gob"

func init() {
	gob.Register(&EntityKey_Ed25519{})
	gob.Register(&EntitySecretKey_Ed25519{})
	gob.Register(&EntityKey_Curve25519{})
	gob.Register(&EntitySecretKey_Ed25519{})
	gob.Register(&EntityKey_IBE_Params_BN256{})
	gob.Register(&EntitySecretKey_IBE_Master_BN256{})
	gob.Register(&EntityKey_IBE_BN256{})
	gob.Register(&EntitySecretKey_IBE_BN256{})
	gob.Register(&EntityKey_OAQUE_BN256_S20_Params{})
	gob.Register(&EntitySecretKey_OAQUE_BN256_S20_Master{})
	gob.Register(&EntityKey_OAQUE_BN256_S20{})
	gob.Register(&EntitySecretKey_OAQUE_BN256_S20{})
	gob.Register(&LocationSchemeInstanceURL{})
	gob.Register(&HashSchemeInstance_Keccak_256{})
	gob.Register(&HashSchemeInstance_Sha3_256{})
	gob.Register(&CommitmentRevocationSchemeInstance{})
}
