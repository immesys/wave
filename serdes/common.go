package serdes

import (
	"math/big"

	"github.com/immesys/asn1"
)

var (
	WaveOID                               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157}
	WaveObjectOID                         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2}
	AttestationOID                        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 1}
	EntityOID                             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 2}
	ExplicitProofOID                      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 3}
	AttestationBodySchemeOID              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3}
	UnencryptedBodyOID                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3, 1}
	WR1BodyOID                            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3, 2}
	AttestationReferenceKeySchemeOID      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 4}
	OuterSignatureSchemeOID               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 5}
	EphemeralEd25519OID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 5, 1}
	OuterSignatureBindingSchemeOID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 6}
	SignedOuterKeyOID                     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 6, 1}
	LocationSchemeOID                     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 8}
	LocationURLOID                        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 8, 1}
	LocationEthereumOID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 8, 2}
	HashSchemeOID                         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 9}
	Sha3_256OID                           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 9, 1}
	Keccak_256OID                         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 9, 2}
	RevocationSchemeOID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 10}
	CommitmentRevocationOID               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 10, 1}
	EntityKeySchemeOID                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11}
	EntityEd25519OID                      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11, 1}
	EntityCurve25519OID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11, 2}
	EntityOAQUE_BN256_S20_AttributeSetOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11, 3}
	EntityOAQUE_BN256_S20_ParamsOID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11, 4}
	PolicySchemeOID                       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 12}
	TrustLevelPolicyOID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 12, 1}
	ResourceTreePolicyOID                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 12, 2}
	PolicyAddendumOID                     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 13}
	WR1KeyMaterialOID                     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 13, 1}
	EntitySecretKeySchemeOID              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14}
	EntitySecretEd25519OID                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 1}
	EntitySecretCurve25519OID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 2}
	EntitySecretOAQUE_BN256_S20OID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 3}
	EntitySecretOAQUE_BN256_S20_MasterOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 4}
	EntityKeyringSchemeOID                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 15}
	PlaintextKeyringOID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 15, 1}
	AES128_GCM_PBKDF2OID                  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 15, 2}
)

type Keccak_256 []byte
type Sha3_256 []byte
type Ed25519PublicKey []byte
type Curve25519PublicKey []byte
type OAQUE_BN256_S20_AttributeSet []byte
type OAQUE_BN256_S20_Params []byte

func init() {
	//Our custom ASN1 parser can parse external types if we register them in
	//advance
	asn1.RegisterExternalType(EntityOID, &WaveEntity{})
	asn1.RegisterExternalType(CommitmentRevocationOID, &CommitmentRevocation{})
	asn1.RegisterExternalType(Sha3_256OID, &Sha3_256{})
	asn1.RegisterExternalType(Keccak_256OID, &Keccak_256{})
	asn1.RegisterExternalType(LocationURLOID, &LocationURL{})
	asn1.RegisterExternalType(LocationEthereumOID, &LocationEthereum{})
	asn1.RegisterExternalType(EntityEd25519OID, &Ed25519PublicKey{})
	asn1.RegisterExternalType(EntityCurve25519OID, &Curve25519PublicKey{})
	asn1.RegisterExternalType(EntityOAQUE_BN256_S20_AttributeSetOID, &OAQUE_BN256_S20_AttributeSet{})
	asn1.RegisterExternalType(EntityOAQUE_BN256_S20_ParamsOID, &OAQUE_BN256_S20_Params{})
}

// WaveWireObject is used whenever an object is stored externally or transmitted.
// it wraps the object with the necessary type information to permit decoding without
// knowing what the object will be
type WaveWireObject struct {
	Content asn1.External
}

type RevocationOption struct {
	Critical bool
	Scheme   asn1.External
}

type Extension struct {
	ExtensionID asn1.ObjectIdentifier
	Critical    bool
	Value       []byte
}

type CommitmentRevocation struct {
	Hash     asn1.External
	Location asn1.External
}

type LocationURL struct {
	Value string
}
type LocationEthereum struct {
	ChainID         int
	ContractAddress *big.Int
}
