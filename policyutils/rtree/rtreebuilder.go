package rtree

import (
	"bytes"
	"context"
	"fmt"
	"math/bits"
	"sort"

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
		//.Printf("beginning BFS depth %d (<%d)\n", bfsdepth, maxbfsdepth)
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
			//fmt.Printf("rechecking for final solution (%d sols)\n", len(sols))
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
		//fmt.Printf("finished BFS depth %d, new border is %d elements\n", bfsdepth, len(nextgraphborder))
		graphborder = nextgraphborder
	}
	//fmt.Printf("done: %v\n", tb.finalSolution)
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

// SolutionExists is utility function that checks if a solution is possible
//complexity is O(n) where n is the size of the solution slice
func (n *Node) SolutionExists(v uint64) bool {
	var i uint64
	for _, sol := range n.Solutions {
		i = i | sol.Bits
	}
	return i&v == v
}

// GetAllSolutionsForOnePermission is a utility function that returns all solutions in n that match a given permission
func (n *Node) GetAllSolutionsForOnePermission(v uint64) []*Solution {
	rv := []*Solution{}
	for _, sol := range n.Solutions {
		if sol.Bits == v {
			rv = append(rv, sol)
		}
	}
	return rv
}

// GetAllSolutionsForPermissions is a utility function that takes a subset of permissions that matches a given target
// and finds all solutions in n.Solutions that combine these permissions
// if there are solutions in n that have the same permission there will be multiple solutions
func (n *Node) GetAllSolutionsForPermissions(arr []uint64, v uint64) []*Solution {
	s_arr := len(arr)
	rv := []*Solution{}
	if s_arr <= 0 {
		return rv
	}
	twodsolns := make([][]*Solution, s_arr, s_arr)
	for i, p := range arr {
		twodsolns[i] = n.GetAllSolutionsForOnePermission(p)
	}
	// keep track of the size of each inner array
	sizearr := make([]int, s_arr, s_arr)
	// keep track of the index of each inner array which will be used
	// to make the next combination
	cntarr := make([]int, s_arr, s_arr)

	// Discover the size of each inner array and populate sizearr.
	// Also calculate the total number of combinations possible using the
	// inner array sizes.
	total := 1
	for i := range arr {
		sizearr[i] = len(twodsolns[i])
		total *= len(twodsolns[i])
	}
	for cntdn := total; cntdn > 0; cntdn-- {
		// Run through the inner arrays, grabbing the member from the index
		// specified by the cntarr for each inner array, and build a
		// combination solution.
		combination := []*Solution{}
		for i := 0; i < s_arr; i++ {
			combination = append(combination, twodsolns[i][cntarr[i]])
		}
		if len(combination) > 0 {
			csol := combination[0]
		ADDSOLS:
			for i := 1; i < len(combination); i++ {
				csol = csol.Combine(combination[i])
				if csol == nil {
					break ADDSOLS
				}
			}
			if csol != nil && ((csol.Bits & v) == v) {
				rv = append(rv, csol)
			}
		}
		// Now we need to increment the cntarr so that the next
		// combination is taken on the next iteration of this loop.
		for incidx := s_arr - 1; incidx >= 0; incidx-- {
			if cntarr[incidx]+1 < sizearr[incidx] {
				cntarr[incidx]++
				// None of the indices of higher significance need to be
				// incremented, so jump out of this for loop at this point.
				break
			}
			// The index at this position is at its max value, so zero it
			// and continue this loop to increment the index which is more
			// significant than this one.
			cntarr[incidx] = 0
		}
	}
	return rv
}

//BitBacktrackSubsetSum returns a 2d slice where each slice is a subset solution
//for a given target using backtracking
func BitBacktrackSubsetSum(arr []uint64, n int, t uint64) [][]uint64 {
	// get sum (or) of all elements from X0->Xn and pass as array
	arrsum := make([]uint64, n)
	sum := uint64(0)
	for i := 0; i < n; i++ {
		sum = sum | arr[i]
		arrsum[i] = sum
	}
	if t&arrsum[n-1] != t {
		return nil
	}
	return BitBacktrackRecurse(arr, arrsum, n-1, t)
}

//BitBacktrackRecurse is the internal recursive function for BitBacktrackSubsetSum
func BitBacktrackRecurse(arr []uint64, sum []uint64, n int, t uint64) [][]uint64 {
	// if zero target or empty set
	if t == uint64(0) || n < 0 {
		return nil
	}

	// if the set has a single element return it if it matches the target
	if n == 0 {
		if arr[n]&t == t {
			return [][]uint64{[]uint64{arr[n]}}
		}
		return nil
	}

	// if target is greater than sum return
	if sum[n]&t != t {
		return nil
	}

	// if target equals Xn append Xn to solution set and return BitSubsetSum([X0,Xn-1])
	var s [][]uint64
	if arr[n]&t == t {
		s = append(s, []uint64{arr[n]})
		if t == sum[n-1]&t {
			y := BitBacktrackRecurse(arr, sum, n-1, t)
			if y != nil {
				for _, i := range y {
					s = append(s, i)
				}
			}
		}
		return s
	}

	// if Xn adds more permission then try including it
	if arr[n]&t != uint64(0) {
		rt := (t &^ arr[n])
		if sum[n-1]&rt == rt {
			y := BitBacktrackRecurse(arr, sum, n-1, rt)
			if y != nil {
				for _, i := range y {
					i = append(i, arr[n])
					s = append(s, i)
				}
			}
		}
	}
	if t == sum[n-1]&t {
		y := BitBacktrackRecurse(arr, sum, n-1, t)
		if y != nil {
			for _, i := range y {
				s = append(s, i)
			}
		}
	}

	return s
}

//BitDPSubsetSum returns a 2d slice where each slice is a subset solution
//for a given target using dynamic programming
func BitDPSubsetSum(arr []uint64, n int, t uint64) [][]uint64 {
	// if zero target or empty set
	if t == 0 || n <= 0 {
		return nil
	}

	// if target is greater than sum of all permissions return
	sum := uint64(0)
	for i := 0; i < n; i++ {
		sum = sum | arr[i]
	}
	if t&sum != t {
		return nil
	}

	// add different permission combinations that form the target permission
	var tarr []uint64
	tmap := make(map[uint64]int)

	idx := 0
	for p := uint64(0); p < t+1; p++ {
		if p&^t == uint64(0) {
			tmap[p] = idx
			idx++
			tarr = append(tarr, p)
		}
	}
	tlen := len(tarr)
	dp := make([][]bool, n)
	for j, _ := range dp {
		dp[j] = make([]bool, tlen)
	}

	// 0 permission can be made with an empty set
	for i := 0; i < n; i++ {
		dp[i][0] = true
	}

	// fill in first row if permission can be made using just first element only then set to true
	for j := 1; j < tlen; j++ {
		dp[0][j] = (arr[0]&tarr[j] == tarr[j])
	}

	// fill in the rest of dp
	for i := 1; i < n; i++ {
		for j := 1; j < tlen; j++ {
			if arr[i]&tarr[j] == 0 { //if permission cannot be made using this element then set to above value
				dp[i][j] = dp[i-1][j]
			} else { //if all or part of the permission can be made using this element set to above value or to value of the remaining permission
				// fmt.Printf("t:%04b arr:%04b %4b\n", t&^tarr[i])
				dp[i][j] = dp[i-1][j] || dp[i-1][tmap[tarr[j]&^arr[i]]]
			}
		}
	}
	if dp[n-1][tlen-1] == false {
		return nil
	}
	return BitDPRecurse(arr, n-1, t, dp, tmap)
}

//BitDPRecurse is the internal recursive function for BitDPSubsetSum
func BitDPRecurse(arr []uint64, n int, t uint64, dp [][]bool, tmap map[uint64]int) [][]uint64 {
	// if empty set return
	if n < 0 {
		return nil
	}

	// if target is 0 return empty set
	if t == 0 {
		return [][]uint64{[]uint64{}}
	}
	// if there is a single element return it if it matches the target
	if n == 0 && dp[n][tmap[t]] {
		return [][]uint64{[]uint64{arr[n]}}
	}

	var s [][]uint64
	//if target can be made using this element try including it
	if (arr[n]&t != 0 || arr[n]&t == t) && dp[n-1][tmap[t&^arr[n]]] {
		y := BitDPRecurse(arr, n-1, t&^arr[n], dp, tmap)
		if y != nil {
			for _, i := range y {
				i = append(i, arr[n])
				s = append(s, i)
			}
		}
	}

	// don't include this element
	if dp[n-1][tmap[t]] {
		y := BitDPRecurse(arr, n-1, t, dp, tmap)
		if y != nil {
			for _, i := range y {
				s = append(s, i)
			}
		}
	}
	return s
}

//FastestSolutionsFor returns combination of max TTL and max permission but not min weight
//complexity is in O(n*l) + O(n*lg(n)) + O(n) where n is the size of the solution slice, l is the size of the permission vector
func (n *Node) FastestSolutionsFor(v uint64) []*Solution {
	// if no solution is possible return empty slice
	if !n.SolutionExists(v) {
		return []*Solution{}
	}
	trv := []*Solution{}
	var rvcnt map[uint64]int

	// loop over solutions and add max TTL and count for each bit O(n*l)
	for i := uint64(1); i <= v; i = i << 1 {
		mx := 0
		//find max TTL for each bit
		for _, sol := range n.Solutions {
			if sol.Bits&i == i {
				if sol.TTL > mx {
					mx = sol.TTL
				}
			}
		}
		//add all solutions with max TTL and increment count if solution is max for more than one bit
		for _, sol := range n.Solutions {
			if sol.TTL == mx && sol.Bits&i == i {
				if rvcnt[sol.Bits] == 0 {
					trv = append(trv, sol)
					rvcnt[sol.Bits] = 1
				} else {
					rvcnt[sol.Bits]++
				}
			}
		}
	}

	//reduce trv list by sorting and returning max TTL and max count for tied TTL
	// sort trv list by TTL then by count O(n*lg(n))
	sort.Slice(trv, func(i, j int) bool {
		if trv[i].TTL < trv[j].TTL {
			return true
		}
		if trv[i].TTL > trv[j].TTL {
			return false
		}
		return rvcnt[trv[i].Bits] < rvcnt[trv[j].Bits]
	})

	// add elements while target is not met O(n)
	rv := []*Solution{}
	var i uint64
	for st := len(trv) - 1; st >= 0; st-- {
		if i&v == v {
			break
		}
		rv = append(rv, trv[st])
		i = i | trv[st].Bits
	}

	// combine all elements to one solution and return it
	// TODO: Michael is this the proper way to combine multiple solutions into a single one?
	if len(rv) > 0 {
		csol := rv[0]
		for j := 1; j < len(rv); j++ {
			csol = csol.Combine(rv[j])
			// This should never happen
			if csol == nil {
				return []*Solution{}
			}
		}
		// This should never happen
		if (csol.Bits & v) != v {
			return []*Solution{}
		}
		//fmt.Printf("Node %s FastestSolutionsFor %x:\n", n.Ref(), v)
		//fmt.Printf(" - %s\n", csol.String())
		return []*Solution{csol}
	}
	return []*Solution{}
}

//BestSolutionsForSmallNorT returns the best solutions for either a small list of permissions of size n
//or a large list of size n but with a small target v
//if bt is true it will use the backtracking algorithm for small n
//if bt is false it will use the dynamic programming algorithm for small v
func (n *Node) BestSolutionsForSmallNorT(v uint64, bt bool) []*Solution {
	// if no solution is possible return empty slice
	if !n.SolutionExists(v) {
		return []*Solution{}
	}
	// trv := []*Solution{}
	// extract bit array from n.Solutions
	// n.Solutions might have multiple solutions with the same permission, only add unique ones
	u := make([]uint64, 0, len(n.Solutions))
	m := make(map[uint64]bool)
	for _, sol := range n.Solutions {
		if _, ok := m[sol.Bits]; !ok {
			m[sol.Bits] = true
			u = append(u, sol.Bits)
		}
	}
	// sort array by largest permissions to speed up subsetsum and avoid duplicates
	sort.Slice(u, func(i, j int) bool {
		if bits.OnesCount64(u[i]) < bits.OnesCount64(u[j]) {
			return true
		}
		return false
	})

	// do bt or dp BitSubsetSum based on bool flag
	var y [][]uint64
	if bt {
		y = BitBacktrackSubsetSum(u, len(u), v)
	} else {
		y = BitDPSubsetSum(u, len(u), v)
	}
	// if no solution found for subsetsum return an empty set
	if y == nil {
		return []*Solution{}
	}
	// create solutions for each subset and add them to the list of possible solutions
	rv := []*Solution{}

	for _, i := range y {
		solns := n.GetAllSolutionsForPermissions(i, v)
		for _, sol := range solns {
			rv = append(rv, sol)
		}
	}

	//fmt.Printf("Node %s BestSolutionsFor %x, prereduction:\n", n.Ref(), v)
	for _, _ = range rv {
		//fmt.Printf(" - %s\n", el.String())
	}
	// reduce list
	reduced := reduceSolutionList(rv)
	//fmt.Printf("Post reduction:\n")
	for _, _ = range reduced {
		//fmt.Printf(" - %s\n", el.String())
	}
	return reduced
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
	//fmt.Printf("Node %s BestSolutionsFor %x, prereduction:\n", n.Ref(), v)
	for _, _ = range rv {
		//fmt.Printf(" - %s\n", el.String())
	}
	reduced := reduceSolutionList(rv)
	//fmt.Printf("Post reduction:\n")
	for _, _ = range reduced {
		//fmt.Printf(" - %s\n", el.String())
	}
	return reduced
}

// BruteForceSolutionsFor finds all combinations and adds them if they match the target permission
func (n *Node) BruteForceSolutionsFor(v uint64) []*Solution {
	rv := []*Solution{}
	s := len(n.Solutions)
	for num := 0; num < (1 << uint(s)); num++ {
		combination := []*Solution{}
		for ndx := 0; ndx < s; ndx++ {
			// (is the bit "on" in this number?)
			if num&(1<<uint(ndx)) != 0 {
				// (then add it to the combination)
				combination = append(combination, n.Solutions[ndx])
			}
		}
		if len(combination) > 0 {
			csol := combination[0]
		ADDSOLS:
			for i := 1; i < len(combination); i++ {
				csol = csol.Combine(combination[i])
				if csol == nil {
					break ADDSOLS
				}
			}
			if csol != nil && ((csol.Bits & v) == v) {
				rv = append(rv, csol)
			}
		}
	}
	//fmt.Printf("Node %s BestSolutionsFor %x, prereduction:\n", n.Ref(), v)
	for _, _ = range rv {
		//fmt.Printf(" - %s\n", el.String())
	}
	reduced := reduceSolutionList(rv)
	//fmt.Printf("Post reduction:\n")
	for _, _ = range reduced {
		//fmt.Printf(" - %s\n", el.String())
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
				spew.Dump(pol)
				spew.Dump(rhs)
				spew.Dump(msg)
				//fmt.Printf("msg: %v %v\n", msg, err)
				panic("we should not be here")
			}
			pol = result
		}
		indep_policies = append(indep_policies, pol)
	}
	combined_policy := indep_policies[0]
	for _, pol := range indep_policies[1:] {
		result, okay, _, err := combined_policy.Union(pol)
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
			//n.tb.wout("skipping %s : invalid", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}
		if lres.Attestation.DecryptedBody == nil {
			//n.tb.wout("skipping %s : not decrypted", lres.Attestation.Keccak256HI().MultihashString())
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
			//n.tb.wout("skipping %s : not RTree", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}
		err = rtpol.CheckValid()
		if err != nil {
			//n.tb.wout("skipping %s : policy invalid", lres.Attestation.Keccak256HI().MultihashString())
			continue nextAttestation
		}

		wtr := WrappedRTreePolicy(*rtpol)
		edge.Policy = &wtr
		bits, err := edge.Policy.Bitset(n.tb.ref)
		if bits == 0 || err != nil {
			//n.tb.wout("skipping %s : permissions don't apply", lres.Attestation.Keccak256HI().MultihashString())
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
	//fmt.Printf("updating solutions at node %s, src is %s\n", n.Ref(), src.Ref())
	askfor := make(map[uint64]bool)
	for _, sol := range src.Solutions {
		if sol.Bits&edge.Bits == 0 {
			//This solution doesn't go through the edge
			//fmt.Printf("source solution doesn't pass thorugh edge\n")
			continue
		}
		askfor[sol.Bits&edge.Bits] = true
	}
	for _, sol := range n.Solutions {
		if sol.Bits&edge.Bits == 0 {
			//fmt.Printf("dst solution doesn't pass thorugh edge\n")
			//This solution doesn't go through the edge
			continue
		}
		askfor[sol.Bits&edge.Bits] = true
	}
	//fmt.Printf("updatesol will ask for:\n")
	//spew.Dump(askfor)
	newsolutions := []*Solution{}
	for bits := range askfor {
		sols := src.BestSolutionsFor(bits)
		for _, sol := range sols {
			if sol.TTL == 0 {
				//fmt.Printf("Skipping TTL 0 solution\n")
				continue
			}
			nsol := sol.Extend(edge)
			if nsol == nil {
				panic("do we expect this?")
			}
			newsolutions = append(newsolutions, nsol)
		}
		//fmt.Printf("got back %d sols for ask of %x\n", len(sols), bits)
	}
	allsolutions := append(n.Solutions, newsolutions...)
	//	fmt.Printf("node %s updatesol, preprune:\n", n.Ref())
	for _, _ = range allsolutions {
		//fmt.Printf(" - %s\n", el.String())
	}
	pruned_solutions := reduceSolutionList(allsolutions)
	n.Solutions = pruned_solutions
	//fmt.Printf("node %s setting solutions to:\n", n.Ref())
	for _, _ = range pruned_solutions {
		//fmt.Printf(" - %s\n", el.String())
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
