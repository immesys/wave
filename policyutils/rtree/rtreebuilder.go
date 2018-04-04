package rtree

import (
	"bytes"
	"context"
	"fmt"

	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
)

type RTreeBuilder struct {
	eng           *engine.Engine
	ctx           context.Context
	out           chan string
	outputEnabled bool
	subject       iapi.HashSchemeInstance
	start         iapi.HashSchemeInstance

	ref *BitsetReference
}

type Params struct {
	Subject iapi.HashSchemeInstance
	Engine  *engine.Engine
	Policy  *iapi.RTreePolicy
	//Typically the domain authority
	Start        iapi.HashSchemeInstance
	EnableOutput bool
}

func NewRTreeBuilder(ctx context.Context, p *Params) (*RTreeBuilder, error) {
	return &RTreeBuilder{
		eng:           p.Engine,
		ctx:           ctx,
		outputEnabled: p.EnableOutput,
		subject:       p.Subject,
		start:         p.Start,
	}, nil
}

func (tb *RTreeBuilder) Build(msgs chan string) {
	tb.out = msgs
	tb.build()
}

func (tb *RTreeBuilder) wout(fmts string, args ...interface{}) {
	if !tb.outputEnabled {
		return
	}
	select {
	case tb.out <- fmt.Sprintf(fmts, args...):
	case <-tb.ctx.Done():
	}
}

func (tb *RTreeBuilder) build() {

}

type BitsetReference struct {
	DomainMultihash []byte
	//map permissionset_mh_string -> permission -> bit
	Mapping map[string]map[string][]Bit
	Bits    uint64
}
type Bit struct {
	URI string
	Bit uint
}

type Edge struct {
	Attestation *iapi.Attestation
	Policy      *WrappedRTreePolicy
	Bits        uint64
}

type Solution struct {
	Bits  uint64
	Paths [][]*Edge
	TTL   int
	//Multihash -> attestation
	Set      map[string]*Edge
	Terminal *Node
}

type Node struct {
	tb        *RTreeBuilder
	Hash      iapi.HashSchemeInstance
	Solutions []*Solution
	Edges     []*Edge
}

func (n *Node) BestSolutionsFor(v uint64) []*Solution {
	panic("moustafa doing this")
}

func (e *Edge) Dst() *Node {
	panic("ni")
}
func (e *Edge) Ref() string {
	return e.Attestation.Keccak256HI().MultihashString()
}

func (n *Node) Ref() string {
	return n.Hash.MultihashString()
}

func (n *Node) Out() []*Edge {
	if n.Edges != nil {
		return n.Edges
	}
	rv := []*Edge{}
	lr, le := n.tb.eng.LookupAttestationsFrom(n.tb.ctx, n.Hash, &iapi.LookupFromFilter{
		Valid: iapi.Bool(true),
	})
nextAttestation:
	for lres := range lr {
		if !lres.Validity.Valid {
			n.tb.wout("skipping %s : invalid", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}
		if lres.Attestation.DecryptedBody == nil {
			n.tb.wout("skipping %s : not decrypted", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}
		edge := Edge{}
		edge.Attestation = lres.Attestation
		pol, err := iapi.PolicySchemeInstanceFor(&lres.Attestation.DecryptedBody.VerifierBody.Policy)
		if err != nil {
			panic(err)
		}
		rtpol, ok := pol.(*iapi.RTreePolicy)
		if !ok {
			n.tb.wout("skipping %s : not RTree", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}
		err = rtpol.CheckValid()
		if err != nil {
			n.tb.wout("skipping %s : policy invalid", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}

		wtr := WrappedRTreePolicy(*rtpol)
		edge.Policy = &wtr
		bits, err := edge.Policy.Bitset(n.tb.ref)
		if bits == 0 || err != nil {
			n.tb.wout("skipping %s : permissions don't apply", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}
		edge.Bits = bits
		rv = append(rv, &edge)
	}
	if e := <-le; e != nil {
		panic(e)
	}
	n.Edges = rv
	return rv
}

type CompareResult int

const Better CompareResult = 1
const Worse CompareResult = 2
const Different CompareResult = 3

func (lhs *Solution) CompareTo(rhs *Solution) CompareResult {
	panic("ni")
}
func (s *Solution) Weight() int {
	return len(s.Set)
}

type WrappedRTreePolicy iapi.RTreePolicy

func (w *WrappedRTreePolicy) TTL() int {
	return w.SerdesForm.Indirections
}
func (w *WrappedRTreePolicy) GenerateBitsetReference() (*BitsetReference, error) {
	ns := iapi.HashSchemeInstanceFor(&w.SerdesForm.Namespace)
	dh := ns.Multihash()
	bitnum := 0
	var rvbits uint64
	rvref := &BitsetReference{}
	rvref.DomainMultihash = dh
	rvref.Mapping = make(map[string]map[string][]Bit)
	for _, statement := range w.SerdesForm.Statements {
		pset := iapi.HashSchemeInstanceFor(&statement.PermissionSet).MultihashString()
		pset_map, ok := rvref.Mapping[pset]
		if !ok {
			pset_map = make(map[string][]Bit)
		}
		for _, perm := range statement.Permissions {
			bit := Bit{
				URI: statement.Resource,
				Bit: uint(bitnum),
			}
			rvbits |= 1 << bit.Bit
			bitnum++
			pset_map[perm] = append(pset_map[perm], bit)
		}
		rvref.Mapping[pset] = pset_map
	}
	rvref.Bits = rvbits
	return rvref, nil
}

func (w *WrappedRTreePolicy) Bitset(ref *BitsetReference) (uint64, error) {
	var rv uint64
	ns := iapi.HashSchemeInstanceFor(&w.SerdesForm.Namespace)
	dh := ns.Multihash()
	if !bytes.Equal(dh, ref.DomainMultihash) {
		return 0, nil
	}
	for _, statement := range w.SerdesForm.Statements {
		pset := iapi.HashSchemeInstanceFor(&statement.PermissionSet).MultihashString()
		pset_map, ok := ref.Mapping[pset]
		if !ok {
			continue
		}
		for _, perm := range statement.Permissions {
			bits, ok := pset_map[perm]
			if !ok {
				continue
			}
			for _, bit := range bits {
				//Check that the resource is a superset of the required one
				result, ok := iapi.RestrictBy(bit.URI, statement.Resource)
				if !ok || result != bit.URI {
					continue
				}
				rv |= 1 << bit.Bit
			}
		}
	}
	return rv, nil
}

func (tb *RTreeBuilder) Alg() {
	bfsdepth := 1
	maxbfsdepth := 255
	//Find graph border
	graphborder := []*Node{}
	var destnode *Node
	//TODO: add starting node to border
	recheck := false
	for ; bfsdepth < maxbfsdepth; bfsdepth++ {
		for _, src := range graphborder {
			edges := src.Out()
			for _, edge := range edges {
				dst := edge.Dst()
				dst.UpdateSolutions(src, edge)
				if dst.Ref() == destnode.Ref() {
					recheck = true
				}
			}
			if recheck {
				sols := destnode.BestSolutionsFor(tb.ref.Bits)
				weight := -1
				for _, s := range sols {
					if weight == -1 || s.Weight() < weight {
						weight = s.Weight()
					}
				}
				bfsdepth = weight - 1
				recheck = false
			}
		}
	}
	fmt.Printf("done")
}

func (s *Solution) Extend(e *Edge) *Solution {
	rv := &Solution{}
	if s.TTL == 0 {
		return nil
	}
	rv.TTL = s.TTL - 1
	rv.Set = make(map[string]*Edge)
	for e, edge := range s.Set {
		rv.Set[e] = edge
	}
	rv.Set[e.Ref()] = e
	rv.Paths = make([][]*Edge, len(s.Paths))
	for idx, path := range s.Paths {
		np := make([]*Edge, 0, len(path)+1)
		for _, pe := range path {
			np = append(np, pe)
		}
		np = append(np, e)
		rv.Paths[idx] = np
	}
	rv.Bits = s.Bits & e.Bits
	rv.Terminal = e.Dst()
	return rv
}
func (s *Solution) Combine(rhs *Solution) *Solution {
	if s.Terminal != rhs.Terminal {
		panic(fmt.Sprintf("differing nodes %s %s\n", s.Terminal.Ref(), rhs.Terminal.Ref()))
	}
	rv := &Solution{}
	rv.TTL = s.TTL
	if rhs.TTL < s.TTL {
		rv.TTL = rhs.TTL
	}
	rv.Set = make(map[string]*Edge)
	for ref, edge := range s.Set {
		rv.Set[ref] = edge
	}
	for ref, edge := range rhs.Set {
		rv.Set[ref] = edge
	}
	rv.Paths = make([][]*Edge, 0, len(s.Paths)+len(rhs.Paths))
	for _, path := range s.Paths {
		np := make([]*Edge, 0, len(path))
		for _, pe := range path {
			np = append(np, pe)
		}
		rv.Paths = append(rv.Paths, np)
	}
	for _, path := range rhs.Paths {
		np := make([]*Edge, 0, len(path))
		for _, pe := range path {
			np = append(np, pe)
		}
		rv.Paths = append(rv.Paths, np)
	}
	rv.Terminal = s.Terminal
	rv.Bits = s.Bits | rhs.Bits
	return rv
}
func (n *Node) UpdateSolutions(src *Node, edge *Edge) {
	askfor := make(map[uint64]bool)
	for _, sol := range src.Solutions {
		if sol.Bits&edge.Bits == 0 {
			//This solution doesn't go through the edge
			continue
		}
		askfor[sol.Bits&edge.Bits] = true
	}
	for _, sol := range n.Solutions {
		if sol.Bits&edge.Bits == 0 {
			//This solution doesn't go through the edge
			continue
		}
		askfor[sol.Bits&edge.Bits] = true
	}
	newsolutions := []*Solution{}
	for bits := range askfor {
		sols := src.BestSolutionsFor(bits)
		for _, sol := range sols {
			nsol := sol.Extend(edge)
			newsolutions = append(newsolutions, nsol)
		}
	}
	allsolutions := append(n.Solutions, newsolutions...)
	pruned_solutions := reduceSolutionList(allsolutions)
	n.Solutions = pruned_solutions
}

func reduceSolutionList(sol []*Solution) []*Solution {
	rv := []*Solution{}
	for lhs := 0; lhs < len(sol)-1; lhs++ {
		include := true
		for rhs := lhs; rhs < len(sol); rhs++ {
			if sol[lhs].Bits != sol[rhs].Bits {
				continue
			}
			if sol[lhs].Weight() >= sol[rhs].Weight() &&
				sol[lhs].TTL <= sol[rhs].TTL {
				include = false
				break
			}
		}
		if include {
			rv = append(rv, sol[lhs])
		}
	}
	return rv
}
