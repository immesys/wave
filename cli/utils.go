package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/wve"
)

func ReverseName(c pb.WAVEClient, p *pb.Perspective, hash []byte) string {
	resp, err := c.ResolveReverseName(context.Background(), &pb.ResolveReverseNameParams{
		Perspective: p,
		Hash:        hash,
	})
	if err != nil {
		fmt.Printf("could not perform reverse lookup: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		if resp.Error.Code == wve.LookupFailure {
			return "< unknown >"
		}
		fmt.Printf("could not perform reverse lookup: %v\n", resp.Error.Message)
		os.Exit(1)
	}
	return resp.Name
}
func PrintEntity(e *pb.Entity, l *pb.Location, name string) {
	fmt.Printf("= Entity\n")
	if l != nil {
		fmt.Printf("  Location: %s\n", l.AgentLocation)
	}
	fmt.Printf("      Hash: %s\n", base64.URLEncoding.EncodeToString(e.Hash))
	fmt.Printf("  Known as: %s\n", name)
	fmt.Printf("   Created: %s\n", time.Unix(0, e.ValidFrom*1e6))
	fmt.Printf("   Expires: %s\n", time.Unix(0, e.ValidUntil*1e6))
	fmt.Printf("  Validity:\n")
	fmt.Printf("   - Valid: %v\n", e.Validity.Valid)
	fmt.Printf("   - Expired: %v\n", e.Validity.Expired)
	fmt.Printf("   - Malformed: %v\n", e.Validity.Malformed)
	fmt.Printf("   - Revoked: %v\n", e.Validity.Revoked)
	fmt.Printf("   - Message: %v\n", e.Validity.Message)
}

func PrintAttestation(a *pb.Attestation, l *pb.Location, c pb.WAVEClient, p *pb.Perspective) {
	fmt.Printf("= Attestation\n")
	if l != nil {
		fmt.Printf("    Location: %s\n", l.AgentLocation)
	}
	fmt.Printf("        Hash: %s\n", base64.URLEncoding.EncodeToString(a.Hash))
	fmt.Printf("   Partition: %s\n", formatPartition(a.Partition))
	subknown := ReverseName(c, p, a.SubjectHash)
	fmt.Printf("     Subject: %s\n", base64.URLEncoding.EncodeToString(a.SubjectHash))
	fmt.Printf("  Subj. Name: %s\n", subknown)
	fmt.Printf("  SubjectLoc: %s\n", a.SubjectLocation.AgentLocation)
	if a.Body != nil {
		fmt.Printf("     Created: %s\n", time.Unix(0, a.Body.ValidFrom*1e6))
		fmt.Printf("     Expires: %s\n", time.Unix(0, a.Body.ValidUntil*1e6))
		attknown := ReverseName(c, p, a.Body.AttesterHash)
		fmt.Printf("    Attester: %s\n", base64.URLEncoding.EncodeToString(a.Body.AttesterHash))
		fmt.Printf("   Att. Name: %s\n", attknown)
		fmt.Printf(" AttesterLoc: %s\n", a.Body.AttesterLocation.AgentLocation)
	}
	fmt.Printf("  Validity:\n")
	fmt.Printf("   - Readable: %v\n", !a.Validity.NotDecrypted)
	fmt.Printf("   - Revoked: %v\n", a.Validity.Revoked)
	fmt.Printf("   - Malformed: %v\n", a.Validity.Malformed)
	fmt.Printf("   - Subject invalid: %v\n", a.Validity.DstInvalid)
	if !a.Validity.NotDecrypted {
		fmt.Printf("   - Valid: %v\n", a.Validity.Valid)
		fmt.Printf("   - Expired: %v\n", a.Validity.Expired)
		fmt.Printf("   - Attester invalid: %v\n", a.Validity.SrcInvalid)
		fmt.Printf("  Policy: RTree\n")
		fmt.Printf("   - Namespace: %s\n", base64.URLEncoding.EncodeToString(a.Body.Policy.RTreePolicy.Namespace))
		nsknown := ReverseName(c, p, a.Body.Policy.RTreePolicy.Namespace)
		fmt.Printf("   - NS Name: %s\n", nsknown)
		fmt.Printf("   - Indirections: %d\n", a.Body.Policy.RTreePolicy.Indirections)
		fmt.Printf("   - Statements:\n")
		for idx, st := range a.Body.Policy.RTreePolicy.Statements {
			fmt.Printf("     [%02d] Permission set: %s\n", idx, base64.URLEncoding.EncodeToString(st.PermissionSet))
			psetknown := ReverseName(c, p, st.PermissionSet)
			fmt.Printf("          PSET Name: %s\n", psetknown)
			fmt.Printf("          Permissions: %s\n", strings.Join(st.Permissions, ", "))
			fmt.Printf("          URI: %s\n", st.Resource)
		}
	}
}
