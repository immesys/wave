package iapi

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/immesys/asn1"
	"github.com/immesys/wave/serdes"
)

func PolicySchemeInstanceFor(e *asn1.External) (PolicySchemeInstance, error) {
	switch {
	case e.OID.Equal(serdes.TrustLevelPolicyOID):
		return &TrustLevelPolicy{SerdesForm: *e, Trust: e.Content.(serdes.TrustLevel).Trust}, nil
	case e.OID.Equal(serdes.ResourceTreePolicyOID):
		rtp, ok := e.Content.(serdes.RTreePolicy)
		if !ok {
			return &UnsupportedPolicySchemeInstance{*e}, nil
		}
		return &RTreePolicy{SerdesForm: rtp}, nil
	}
	return &UnsupportedPolicySchemeInstance{*e}, nil
}

var _ PolicySchemeInstance = &UnsupportedPolicySchemeInstance{}

type UnsupportedPolicySchemeInstance struct {
	SerdesForm asn1.External
}

func (ps *UnsupportedPolicySchemeInstance) Supported() bool {
	return false
}
func (ps *UnsupportedPolicySchemeInstance) CanonicalForm() *asn1.External {
	return &ps.SerdesForm
}
func (ps *UnsupportedPolicySchemeInstance) WR1DomainEntity() HashSchemeInstance {
	panic("WR1DomainEntity() called on unsupported policy")
}
func (ps *UnsupportedPolicySchemeInstance) WR1Partition() [][]byte {
	panic("WR1Partition() called on unsupported policy")
}

var _ PolicySchemeInstance = &TrustLevelPolicy{}

func NewTrustLevelPolicy(trust int) (*TrustLevelPolicy, error) {
	if trust < 0 || trust > 4 {
		return nil, fmt.Errorf("trust must be between 0 and 4 inclusive")
	}
	cf := serdes.TrustLevel{Trust: trust}
	return &TrustLevelPolicy{SerdesForm: asn1.NewExternal(cf), Trust: trust}, nil
}

type TrustLevelPolicy struct {
	SerdesForm asn1.External
	Trust      int
}

func (ps *TrustLevelPolicy) Supported() bool {
	return true
}
func (ps *TrustLevelPolicy) CanonicalForm() *asn1.External {
	return &ps.SerdesForm
}

func (ps *TrustLevelPolicy) WR1DomainEntity() HashSchemeInstance {
	return nil
}
func (ps *TrustLevelPolicy) WR1Partition() [][]byte {
	return make([][]byte, 20)
}

type RTreePolicy struct {
	SerdesForm    serdes.RTreePolicy
	VisibilityURI [][]byte
}

func NewRTreePolicyScheme(policy serdes.RTreePolicy, visuri [][]byte) (*RTreePolicy, error) {
	if len(visuri) > 20 {
		return nil, fmt.Errorf("too many elements in visibility URI")
	}
	vuri := make([][]byte, 20)
	for idx, p := range visuri {
		vuri[idx] = p
	}
	return &RTreePolicy{
		SerdesForm:    policy,
		VisibilityURI: vuri,
	}, nil
}

func (ps *RTreePolicy) Supported() bool {
	return true
}
func (ps *RTreePolicy) CanonicalForm() *asn1.External {
	ext := asn1.NewExternal(ps.SerdesForm)
	return &ext
}

func (ps *RTreePolicy) WR1DomainEntity() HashSchemeInstance {
	return HashSchemeInstanceFor(&ps.SerdesForm.Namespace)
}
func (ps *RTreePolicy) WR1Partition() [][]byte {
	return ps.VisibilityURI
}

const PermittedPrimaryStatements = 10
const PermittedCombinedStatements = 1000

//Don't change this without rewriting tree builder
const PermittedPermissions = 64

//This is only valid for attestation policies not derived policies from
//intersections
func (ps *RTreePolicy) CheckValid() error {
	if len(ps.SerdesForm.Statements) > PermittedPrimaryStatements {
		return fmt.Errorf("Too many statements in RTree policy")
	}
	totalPermissions := 0
	for sidx, s := range ps.SerdesForm.Statements {
		totalPermissions += len(s.Permissions)
		valid, _, _ := AnalyzeSuffix(s.Resource)
		if !valid {
			return fmt.Errorf("Statement %d has an invalid resource", sidx)
		}
	}
	if totalPermissions > PermittedPermissions {
		return fmt.Errorf("Policy has too many permission:resource combinations (max %d)", PermittedPermissions)
	}
	return nil
}

//The intersection of two RTreePolicies is the set of permissions that they would
//grant if they appeared in succession in an attestation chain
//This function does not check indirections
//This function assumes the policy has been checked
func (lhs *RTreePolicy) Intersect(rhs *RTreePolicy) (result *RTreePolicy, okay bool, message string, err error) {
	rv := &RTreePolicy{
	//We do not copy the VisibilityURI
	}
	rhs_ns := HashSchemeInstanceFor(&rhs.SerdesForm.Namespace)
	lhs_ns := HashSchemeInstanceFor(&lhs.SerdesForm.Namespace)
	if !bytes.Equal(rhs_ns.Multihash(), lhs_ns.Multihash()) {
		return nil, false, "different authority domain", nil
	}
	statements := []serdes.RTreeStatement{}
	for lhs_idx := 0; lhs_idx < len(lhs.SerdesForm.Statements); lhs_idx++ {
		for rhs_idx := 0; rhs_idx < len(rhs.SerdesForm.Statements); rhs_idx++ {
			interStatement, okay := intersectStatement(
				&lhs.SerdesForm.Statements[lhs_idx],
				&rhs.SerdesForm.Statements[rhs_idx])
			if okay {
				statements = append(statements, *interStatement)
			}
		}
	}

	//Now remove redundant statements
	dedup_statements := []serdes.RTreeStatement{}

next:
	for orig_idx := 0; orig_idx < len(statements); orig_idx++ {
		for chosen_idx := 0; chosen_idx < len(dedup_statements); chosen_idx++ {
			if isStatementSupersetOf(&statements[orig_idx], &dedup_statements[chosen_idx]) {
				//We already have a statement more powerful
				continue next
			}
			if isStatementSupersetOf(&dedup_statements[chosen_idx], &statements[orig_idx]) {
				//This statement is more powerful than one we have chosen. Swap them
				dedup_statements[chosen_idx] = statements[orig_idx]
				continue next
			}

		}
		//This statement is useful
		dedup_statements = append(dedup_statements, statements[orig_idx])
	}

	rv.SerdesForm = serdes.RTreePolicy{
		Namespace: lhs.SerdesForm.Namespace,
	}
	if lhs.SerdesForm.Indirections < rhs.SerdesForm.Indirections {
		rv.SerdesForm.Indirections = lhs.SerdesForm.Indirections - 1
	} else {
		rv.SerdesForm.Indirections = rhs.SerdesForm.Indirections - 1
	}
	rv.SerdesForm.Statements = dedup_statements

	//Check errors
	if rv.SerdesForm.Indirections < 0 {
		return nil, false, "insufficient permitted indirections", nil
	}
	if len(rv.SerdesForm.Statements) > PermittedCombinedStatements {
		return nil, false, "statements form too many combinations", nil
	}

	//TODO maybe calculate wr1 partitions and stuff for derived policy too?
	return rv, true, "", nil
}

func (lhs *RTreePolicy) IsSubsetOf(superset *RTreePolicy) bool {
	superset_ns := HashSchemeInstanceFor(&superset.SerdesForm.Namespace)
	lhs_ns := HashSchemeInstanceFor(&lhs.SerdesForm.Namespace)
	if !bytes.Equal(superset_ns.Multihash(), lhs_ns.Multihash()) {
		return false
	}
nextStatement:
	for _, st := range lhs.SerdesForm.Statements {
		for _, ss := range superset.SerdesForm.Statements {
			if isStatementSupersetOf(&st, &ss) {
				continue nextStatement
			}
		}
		return false
	}
	return true
}
func isStatementSupersetOf(subset *serdes.RTreeStatement, superset *serdes.RTreeStatement) bool {
	lhs_ps := HashSchemeInstanceFor(&subset.PermissionSet)
	rhs_ps := HashSchemeInstanceFor(&superset.PermissionSet)
	if !HashSchemeInstanceEqual(lhs_ps, rhs_ps) {
		return false
	}
	superset_perms := make(map[string]bool)
	for _, perm := range superset.Permissions {
		superset_perms[perm] = true
	}
	for _, perm := range subset.Permissions {
		if !superset_perms[perm] {
			return false
		}
	}
	inter_uri, okay := RestrictBy(subset.Resource, superset.Resource)
	if !okay {
		return false
	}
	return inter_uri == subset.Resource
}
func intersectStatement(lhs *serdes.RTreeStatement, rhs *serdes.RTreeStatement) (result *serdes.RTreeStatement, okay bool) {
	lhs_ps := HashSchemeInstanceFor(&lhs.PermissionSet)
	rhs_ps := HashSchemeInstanceFor(&rhs.PermissionSet)
	if !HashSchemeInstanceEqual(lhs_ps, rhs_ps) {
		return nil, false
	}
	lhs_perms := make(map[string]bool)
	for _, perm := range lhs.Permissions {
		lhs_perms[perm] = true
	}
	intersectionPerms := []string{}
	for _, rperm := range rhs.Permissions {
		if lhs_perms[rperm] {
			intersectionPerms = append(intersectionPerms, rperm)
		}
	}
	if len(intersectionPerms) == 0 {
		return nil, false
	}
	//Now to intersect the resource itself:
	intersectionResource, okay := RestrictBy(lhs.Resource, rhs.Resource)
	if !okay {
		return nil, false
	}
	return &serdes.RTreeStatement{
		PermissionSet: lhs.PermissionSet,
		Permissions:   intersectionPerms,
		Resource:      intersectionResource,
	}, true
}

// Copied verbatim from bosswave
// RestrictBy takes a topic, and a permission, and returns the intersection
// that represents the from topic restricted by the permission. It took a
// looong time to work out this logic...
func RestrictBy(from string, by string) (string, bool) {
	fp := strings.Split(from, "/")
	bp := strings.Split(by, "/")
	fout := make([]string, 0, len(fp)+len(bp))
	bout := make([]string, 0, len(fp)+len(bp))
	var fsx, bsx int
	for fsx = 0; fsx < len(fp) && fp[fsx] != "*"; fsx++ {
	}
	for bsx = 0; bsx < len(bp) && bp[bsx] != "*"; bsx++ {
	}
	fi, bi := 0, 0
	fni, bni := len(fp)-1, len(bp)-1
	emit := func() (string, bool) {
		for i := 0; i < len(bout); i++ {
			fout = append(fout, bout[len(bout)-i-1])
		}
		return strings.Join(fout, "/"), true
	}
	//phase 1
	//emit matching prefix
	for ; fi < len(fp) && bi < len(bp); fi, bi = fi+1, bi+1 {
		if fp[fi] != "*" && (fp[fi] == bp[bi] || (bp[bi] == "+" && fp[fi] != "*")) {
			fout = append(fout, fp[fi])
		} else if fp[fi] == "+" && bp[bi] != "*" {
			fout = append(fout, bp[bi])
		} else {
			break
		}
	}
	//phase 2
	//emit matching suffix
	for ; fni >= fi && bni >= bi; fni, bni = fni-1, bni-1 {
		if bp[bni] != "*" && (fp[fni] == bp[bni] || (bp[bni] == "+" && fp[fni] != "*")) {
			bout = append(bout, fp[fni])
		} else if fp[fni] == "+" && bp[bni] != "*" {
			bout = append(bout, bp[bni])
		} else {
			break
		}
	}
	//phase 3
	//emit front
	if fi < len(fp) && fp[fi] == "*" {
		for ; bi < len(bp) && bp[bi] != "*" && bi <= bni; bi++ {
			fout = append(fout, bp[bi])
		}
	} else if bi < len(bp) && bp[bi] == "*" {
		for ; fi < len(fp) && fp[fi] != "*" && fi <= fni; fi++ {
			fout = append(fout, fp[fi])
		}
	}
	//phase 4
	//emit back
	if fni >= 0 && fp[fni] == "*" {
		for ; bni >= 0 && bp[bni] != "*" && bni >= bi; bni-- {
			bout = append(bout, bp[bni])
		}
	} else if bni >= 0 && bp[bni] == "*" {
		for ; fni >= 0 && fp[fni] != "*" && fni >= fi; fni-- {
			bout = append(bout, fp[fni])
		}
	}
	//phase 5
	//emit star if they both have it
	if fi == fni && fp[fi] == "*" && bi == bni && bp[bi] == "*" {
		fout = append(fout, "*")
		return emit()
	}
	//Remove any stars
	if fi < len(fp) && fp[fi] == "*" {
		fi++
	}
	if bi < len(bp) && bp[bi] == "*" {
		bi++
	}
	if (fi == fni+1 || fi == len(fp)) && (bi == bni+1 || bi == len(bp)) {
		return emit()
	}
	return "", false
}

//A URI looks like
// a/b/c/d ..
// it has no slash at the start or end. There may be many plusses, and/or one star
// each cell must look like:
// [a-zA-Z0-9-_.\(\),]?[a-zA-Z0-9-_.\(\),]+
// or "+", "*"
// Note that a cell starting with an exclamation point denotes the xattr listing
// tree. It is an error to have more than one exclamation point in
// a URI or for it to occur not at the first character of a cell

//AnalyzeSuffix checks a given URI for schema validity and possession of characteristics
func AnalyzeSuffix(uri string) (valid, hasStar, hasPlus bool) {
	cells := strings.Split(uri, "/")
	valid = false
	hasStar = false
	hasPlus = false

	for _, c := range cells {
		ln := len(c)
		switch ln {
		case 0:
			return
		case 1:
			switch c {
			case "*":
				if hasStar {
					return
				}
				hasStar = true
			case "+":
				hasPlus = true
			default:
				k := c[0]
				if !('0' <= k && k <= '9' ||
					'a' <= k && k <= 'z' ||
					'A' <= k && k <= 'Z' ||
					k == '-' || k == '_' ||
					k == ',' || k == '(' ||
					k == ')' || k == '.') {
					return
				}
			}
		default:
			for i := 0; i < len(c); i++ {
				k := c[i]
				if !('0' <= k && k <= '9' ||
					'a' <= k && k <= 'z' ||
					'A' <= k && k <= 'Z' ||
					k == '-' || k == '_' ||
					k == ',' || k == '(' ||
					k == ')' || k == '.') {
					return
				}
			}
		}
	}
	valid = true
	return
}
