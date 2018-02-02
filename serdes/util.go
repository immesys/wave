package serdes

func DefaultEntityEd25519Capabilities() []int {
	return []int{CapCertification, CapAttestation, CapSigning}
}
