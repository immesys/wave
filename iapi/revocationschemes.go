package iapi

import (
	"bytes"
	"context"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

func RevocationSchemeInstanceFor(op *serdes.RevocationOption) RevocationSchemeInstance {
	if op.Scheme.OID.Equal(serdes.CommitmentRevocationOID) {
		crb, ok := op.Scheme.Content.(serdes.CommitmentRevocation)
		if !ok {
			goto unsupported
		}
		return &CommitmentRevocationSchemeInstance{
			SerdesForm: op,
			CRBody:     &crb,
		}
	}
unsupported:
	return &UnsupportedRevocationSchemeInstance{
		SerdesForm: op,
	}
}

type UnsupportedRevocationSchemeInstance struct {
	SerdesForm *serdes.RevocationOption
}

func (rs *UnsupportedRevocationSchemeInstance) Supported() bool {
	return false
}

func (rs *UnsupportedRevocationSchemeInstance) Critical() bool {
	return rs.SerdesForm.Critical
}

func (rs *UnsupportedRevocationSchemeInstance) Id() string {
	panic("Id called on unsupported revocation scheme instance")
}

func (rs *UnsupportedRevocationSchemeInstance) CanonicalForm() serdes.RevocationOption {
	panic("canonical form called on unsupported revocation option")
}

func (rs *UnsupportedRevocationSchemeInstance) IsRevoked(ctx context.Context, s StorageInterface) (bool, wve.WVE) {
	if rs.Critical() {
		return true, nil
	}
	return false, nil
}

type CommitmentRevocationSchemeInstance struct {
	SerdesForm *serdes.RevocationOption
	CRBody     *serdes.CommitmentRevocation
}

func (rs *CommitmentRevocationSchemeInstance) Supported() bool {
	return true
}

func (rs *CommitmentRevocationSchemeInstance) Critical() bool {
	return rs.SerdesForm.Critical
}

func (rs *CommitmentRevocationSchemeInstance) CanonicalForm() serdes.RevocationOption {
	return *rs.SerdesForm
}

func (rs *CommitmentRevocationSchemeInstance) Id() string {
	return HashSchemeInstanceFor(&rs.CRBody.Hash).MultihashString()
}

func (rs *CommitmentRevocationSchemeInstance) IsRevoked(ctx context.Context, s StorageInterface) (bool, wve.WVE) {
	loc := LocationSchemeInstanceFor(&rs.CRBody.Location)
	if !loc.Supported() {
		return rs.Critical(), nil
	}
	hi := HashSchemeInstanceFor(&rs.CRBody.Hash)
	if !hi.Supported() {
		return rs.Critical(), nil
	}
	rv, err := s.GetBlob(ctx, loc, hi)
	if err != nil && err != ErrObjectNotFound {
		return false, wve.ErrW(wve.StorageError, "could not check revocation in storage", err)
	}
	if err == ErrObjectNotFound {
		return false, nil
	}
	hs := HashSchemeFor(rs.CRBody.Hash)
	readback := hs.Instance(rv)
	if bytes.Equal(readback.Value(), hi.Value()) {
		return true, nil
	}
	return false, wve.Err(wve.StorageError, "storage hash mismatch")
}

func NewCommitmentRevocationSchemeInstance(loc LocationSchemeInstance, critical bool, secrets ...[]byte) *CommitmentRevocationSchemeInstance {
	hash := []byte("revocation")
	for _, s := range secrets {
		hash = append(hash, s...)
	}
	if loc == nil {
		panic("nil location")
	}
	//fmt.Printf("revocation hash 2 is %x\n", hash)
	hi_inner := KECCAK256.Instance(hash)
	hi := KECCAK256.Instance(hi_inner.Value())
	hie := hi.CanonicalForm()
	loce := loc.CanonicalForm()
	RB := serdes.CommitmentRevocation{
		Hash:     *hie,
		Location: *loce,
	}
	SDF := serdes.RevocationOption{
		Critical: critical,
		Scheme:   asn1.NewExternal(RB),
	}
	return &CommitmentRevocationSchemeInstance{
		SerdesForm: &SDF,
		CRBody:     &RB,
	}
}
