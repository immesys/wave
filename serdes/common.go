package serdes

import (
	"encoding/gob"

	"github.com/immesys/asn1"
)

var (
	WaveOID                               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157}
	WaveObjectOID                         = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2}
	AttestationOID                        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 1}
	EntityOID                             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 2}
	ExplicitProofOID                      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 3}
	EntitySecretOID                       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 2, 4}
	AttestationBodySchemeOID              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3}
	UnencryptedBodyOID                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3, 1}
	WR1BodyOID                            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3, 2}
	PSKBodySchemeOID                      = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 3, 3}
	AttestationVerifierKeySchemeOID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 4}
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
	EntityIBE_BN256_ParamsOID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11, 5}
	EntityIBE_BN256_PublicOID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 11, 6}
	PolicySchemeOID                       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 12}
	TrustLevelPolicyOID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 12, 1}
	ResourceTreePolicyOID                 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 12, 2}
	PolicyAddendumOID                     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 13}
	WR1DomainVisibilityKey_IBE_BN256OID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 13, 1}
	WR1PartitionKey_OAQUE_BN256_s20OID    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 13, 2}
	WR1EncryptionKey_OAQUE_BN256_s20OID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 13, 3}
	EntitySecretKeySchemeOID              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14}
	EntitySecretEd25519OID                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 1}
	EntitySecretCurve25519OID             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 2}
	EntitySecretOAQUE_BN256_S20OID        = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 3}
	EntitySecretOAQUE_BN256_S20_MasterOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 4}
	EntitySecretIBE_BN256_MasterOID       = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 5}
	EntitySecretIBE_BN256OID              = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 14, 6}
	EntityKeyringSchemeOID                = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 15}
	PlaintextKeyringOID                   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 15, 1}
	KeyringAES128_GCM_PBKDF2OID           = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 51157, 15, 2}
)

const CapCertification = 1
const CapAttestation = 2
const CapSigning = 3
const CapAuthentication = 4
const CapAuthorization = 5
const CapEncryption = 6

type Keccak_256 []byte
type Sha3_256 []byte

func init() {
	//Our custom ASN1 parser can parse external types if we register them in
	//advance
	tpz := []struct {
		O asn1.ObjectIdentifier
		I interface{}
	}{
		{EntityOID, WaveEntity{}},
		{CommitmentRevocationOID, CommitmentRevocation{}},
		{Sha3_256OID, Sha3_256{}},
		{Keccak_256OID, Keccak_256{}},
		{LocationURLOID, LocationURL{}},
		{LocationEthereumOID, LocationEthereum{}},
		// entity stuff
		// {EntityEd25519OID, Ed25519PublicKey{}},
		// {EntityCurve25519OID, Curve25519PublicKey{}},
		// {EntityOAQUE_BN256_S20_AttributeSetOID, OAQUE_BN256_S20_AttributeSet{}},
		// {EntityOAQUE_BN256_S20_ParamsOID, OAQUE_BN256_S20_Params{}},
		// attestation stuff
		{EphemeralEd25519OID, Ed25519OuterSignature{}},
		{EntityEd25519OID, EntityPublicEd25519{}},
		{EntityCurve25519OID, EntityPublicCurve25519{}},
		{EntityOAQUE_BN256_S20_AttributeSetOID, EntityPublicOAQUE_BN256_s20{}},
		{EntityOAQUE_BN256_S20_ParamsOID, EntityParamsOQAUE_BN256_s20{}},
		{EntityIBE_BN256_ParamsOID, EntityParamsIBE_BN256{}},
		{EntityIBE_BN256_PublicOID, EntityPublicIBE_BN256{}},
		{AttestationOID, WaveAttestation{}},
		{UnencryptedBodyOID, AttestationBody{}},
		{TrustLevelPolicyOID, TrustLevel{}},
		{ResourceTreePolicyOID, RTreePolicy{}},
		{SignedOuterKeyOID, SignedOuterKey{}},

		{EntitySecretEd25519OID, EntitySecretEd25519{}},
		{EntitySecretCurve25519OID, EntitySecretCurve25519{}},
		{EntitySecretOAQUE_BN256_S20OID, EntitySecretOQAUE_BN256_s20{}},
		{EntitySecretOAQUE_BN256_S20_MasterOID, EntitySecretMasterOQAUE_BN256_s20{}},
		{EntitySecretIBE_BN256_MasterOID, EntitySecretMasterIBE_BN256{}},
		{EntitySecretIBE_BN256OID, EntitySecretIBE_BN256{}},

		{WR1DomainVisibilityKey_IBE_BN256OID, WR1DomainVisibilityKey_IBE_BN256{}},
		{WR1PartitionKey_OAQUE_BN256_s20OID, WR1PartitionKey_OAQUE_BN256_s20{}},
		{WR1EncryptionKey_OAQUE_BN256_s20OID, WR1EncryptionKey_OAQUE_BN256_s20{}},
		{PlaintextKeyringOID, EntityKeyring{}},
		{EntitySecretOID, WaveEntitySecret{}},
		{KeyringAES128_GCM_PBKDF2OID, KeyringAESCiphertext{}},
		{PSKBodySchemeOID, PSKBodyCiphertext{}},
		{WR1BodyOID, WR1BodyCiphertext{}},
	}
	for _, t := range tpz {
		asn1.RegisterExternalType(t.O, t.I)
		gob.Register(t.I)
	}
}

//--------------

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
	Value   string `asn1:"utf8"`
	Version int
}
type LocationEthereum struct {
	ChainID         int
	ContractAddress []byte
}
