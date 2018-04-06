package rtree

import (
	"bytes"
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
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
	finalSolution *Solution
	ref           *BitsetReference
	nodes         map[string]*Node
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
	wrappedPolicy := WrappedRTreePolicy(*p.Policy)
	ref, err := wrappedPolicy.GenerateBitsetReference()
	if err != nil {
		return nil, err
	}
	return &RTreeBuilder{
		eng:           p.Engine,
		ctx:           ctx,
		outputEnabled: p.EnableOutput,
		subject:       p.Subject,
		start:         p.Start,
		nodes:         make(map[string]*Node),
		ref:           ref,
	}, nil
}

func (tb *RTreeBuilder) Build(msgs chan string) {
	tb.out = msgs
	tb.build()
}
func (tb *RTreeBuilder) Result() *Solution {
	return tb.finalSolution
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
	bfsdepth := 1
	maxbfsdepth := 255
	//Find graph border
	end := &Node{
		Hash: tb.subject,
		tb:   tb,
	}
	tb.nodes[tb.subject.MultihashString()] = end
	start := &Node{
		Hash: tb.start,
		tb:   tb,
		Solutions: []*Solution{&Solution{
			Bits:  tb.ref.Bits,
			Paths: [][]*Edge{[]*Edge{}},
			TTL:   255,
		}},
	}
	start.Solutions[0].Terminal = start
	tb.nodes[tb.start.MultihashString()] = start
	graphborder := map[string]*Node{}
	graphborder[start.Ref()] = start

	recheck := false
	for ; bfsdepth < maxbfsdepth; bfsdepth++ {
		if len(graphborder) == 0 {
			break
		}
		fmt.Printf("beginning BFS depth %d (<%d)\n", bfsdepth, maxbfsdepth)
		nextgraphborder := map[string]*Node{}
		for _, src := range graphborder {
			edges := src.Out()
			for _, edge := range edges {
				dst := edge.Dst()
				nextgraphborder[dst.Ref()] = dst
				dst.UpdateSolutions(src, edge)
				if dst.Ref() == end.Ref() {
					recheck = true
				}
			}
		}
		if recheck {
			sols := end.BestSolutionsFor(tb.ref.Bits)
			fmt.Printf("rechecking for final solution (%d sols)\n", len(sols))
			weight := -1
			for _, s := range sols {
				if weight == -1 || s.Weight() < weight {
					weight = s.Weight()
					tb.finalSolution = s
				}
			}
			if weight != -1 {
				maxbfsdepth = weight - 1
			}
			recheck = false
		}
		fmt.Printf("finished BFS depth %d, new border is %d elements\n", bfsdepth, len(nextgraphborder))
		graphborder = nextgraphborder
	}
	fmt.Printf("done: %v\n", tb.finalSolution)
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
	tb     *RTreeBuilder
	LRes   *engine.LookupResult
	Policy *WrappedRTreePolicy
	Bits   uint64
}

type Solution struct {
	Bits  uint64
	Paths [][]*Edge
	TTL   int
	//Multihash -> attestation
	Set      map[string]*Edge
	Terminal *Node
}

func (s *Solution) String() string {
	return fmt.Sprintf("(grants=%x TTL=%d Weight=%d)", s.Bits, s.TTL, len(s.Set))
}

type Node struct {
	tb        *RTreeBuilder
	Hash      iapi.HashSchemeInstance
	Solutions []*Solution
	Edges     []*Edge
}

func (n *Node) BestSolutionsFor(v uint64) []*Solution {
	//Placeholder: calculate all solutions requiring 1 or 2 combos
	rv := []*Solution{}
	for _, sol := range n.Solutions {
		if sol.Bits&v == v {
			rv = append(rv, sol)
		}
	}
	for lhs := 0; lhs < len(n.Solutions)-1; lhs++ {
		for rhs := lhs + 1; rhs < len(n.Solutions); rhs++ {
			csol := n.Solutions[lhs].Combine(n.Solutions[rhs])
			if csol != nil && ((csol.Bits & v) == v) {
				rv = append(rv, csol)
			}
		}
	}
	fmt.Printf("Node %s BestSolutionsFor %x, prereduction:\n", n.Ref(), v)
	for _, el := range rv {
		fmt.Printf(" - %s\n", el.String())
	}
	reduced := reduceSolutionList(rv)
	fmt.Printf("Post reduction:\n")
	for _, el := range reduced {
		fmt.Printf(" - %s\n", el.String())
	}
	return reduced
}

func (e *Edge) Dst() *Node {
	subject, _ := e.LRes.Attestation.Subject()
	rv, ok := e.tb.nodes[subject.MultihashString()]
	if ok {
		return rv
	}
	//New node:
	n := &Node{
		Hash:      subject,
		Solutions: []*Solution{},
		tb:        e.tb,
	}
	e.tb.nodes[subject.MultihashString()] = n
	return n
}
func (e *Edge) Ref() string {
	return e.LRes.Attestation.Keccak256HI().MultihashString()
}

func (s *Solution) Policy() *iapi.RTreePolicy {
	indep_policies := []*iapi.RTreePolicy{}
	for _, path := range s.Paths {
		lpol := iapi.RTreePolicy(*path[0].Policy)
		pol := &lpol
		for _, el := range path[1:] {
			rhs := iapi.RTreePolicy(*el.Policy)
			result, okay, msg, err := pol.Intersect(&rhs)
			if err != nil {
				panic(err)
			}
			if !okay {
				fmt.Printf("msg: %v %v\n", msg, err)
				panic("we should not be here")
			}
			pol = result
		}
		indep_policies = append(indep_policies, pol)
	}

	combined_policy := indep_policies[0]
	for _, pol := range indep_policies[1:] {
		result, okay, _, err := combined_policy.Intersect(pol)
		if err != nil {
			panic(err)
		}
		if !okay {
			panic("maybe we can be here")
		}
		combined_policy = result
	}

	return combined_policy
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
		edge := Edge{
			tb: n.tb,
		}
		edge.LRes = lres
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

func (s *Solution) Extend(e *Edge) *Solution {
	rv := &Solution{}
	if s.TTL == 0 {
		return nil
	}
	rv.TTL = s.TTL - 1
	if e.Policy.TTL() < rv.TTL {
		rv.TTL = e.Policy.TTL()
	}
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
	fmt.Printf("updating solutions at node %s, src is %s\n", n.Ref(), src.Ref())
	askfor := make(map[uint64]bool)
	for _, sol := range src.Solutions {
		if sol.Bits&edge.Bits == 0 {
			//This solution doesn't go through the edge
			fmt.Printf("source solution doesn't pass thorugh edge\n")
			continue
		}
		askfor[sol.Bits&edge.Bits] = true
	}
	for _, sol := range n.Solutions {
		if sol.Bits&edge.Bits == 0 {
			fmt.Printf("dst solution doesn't pass thorugh edge\n")
			//This solution doesn't go through the edge
			continue
		}
		askfor[sol.Bits&edge.Bits] = true
	}
	fmt.Printf("updatesol will ask for:\n")
	spew.Dump(askfor)
	newsolutions := []*Solution{}
	for bits := range askfor {
		sols := src.BestSolutionsFor(bits)
		for _, sol := range sols {
			if sol.TTL == 0 {
				fmt.Printf("Skipping TTL 0 solution\n")
				continue
			}
			nsol := sol.Extend(edge)
			if nsol == nil {
				panic("do we expect this?")
			}
			newsolutions = append(newsolutions, nsol)
		}
		fmt.Printf("got back %d sols for ask of %x\n", len(sols), bits)
	}
	allsolutions := append(n.Solutions, newsolutions...)
	fmt.Printf("node %s updatesol, preprune:\n", n.Ref())
	for _, el := range allsolutions {
		fmt.Printf(" - %s\n", el.String())
	}
	pruned_solutions := reduceSolutionList(allsolutions)
	n.Solutions = pruned_solutions
	fmt.Printf("node %s setting solutions to:\n", n.Ref())
	for _, el := range pruned_solutions {
		fmt.Printf(" - %s\n", el.String())
	}
}

func reduceSolutionList(sol []*Solution) []*Solution {
	dedup_list := []*Solution{}

next:
	for orig_idx := 0; orig_idx < len(sol); orig_idx++ {
		for chosen_idx := 0; chosen_idx < len(dedup_list); chosen_idx++ {
			if sol[orig_idx].Bits != dedup_list[chosen_idx].Bits {
				continue
			}
			if sol[orig_idx].Weight() >= dedup_list[chosen_idx].Weight() &&
				sol[orig_idx].TTL <= dedup_list[chosen_idx].TTL {
				continue next
			}

			if sol[orig_idx].Weight() <= dedup_list[chosen_idx].Weight() &&
				sol[orig_idx].TTL >= dedup_list[chosen_idx].TTL {
				dedup_list[chosen_idx] = sol[orig_idx]
				continue next
			}
		}
		dedup_list = append(dedup_list, sol[orig_idx])
	}
	return dedup_list
}
