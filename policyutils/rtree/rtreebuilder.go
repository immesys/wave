package rtree

import (
	"context"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/immesys/wave/engine"
	"github.com/immesys/wave/iapi"
)

type RTreeBuilder struct {
	eng           *engine.Engine
	pred          PredicateFunc
	ctx           context.Context
	out           chan string
	outputEnabled bool
	scenarios     []*scenario
	solutions     []*scenario
	subject       iapi.HashSchemeInstance
	start         iapi.HashSchemeInstance
}

type scenario struct {
	policy   *iapi.RTreePolicy
	thisAtt  *engine.LookupResult
	parent   *scenario
	terminal iapi.HashSchemeInstance
	weight   int
}

type Solution struct {
	Attestations []*engine.LookupResult
	Policy       *iapi.RTreePolicy
  need to code this still
  ExplicitProof *serdes.
}

func (s *scenario) ToSolution() *Solution {
	rv := Solution{
		Policy: s.policy,
	}
	reverseAtt := []*engine.LookupResult{s.thisAtt}
	parent := s.parent
	for parent != nil {
		reverseAtt = append(reverseAtt, parent.thisAtt)
		parent = parent.parent
	}
	rv.Attestations = make([]*engine.LookupResult, len(reverseAtt))
	for idx, att := range reverseAtt {
		rv.Attestations[len(reverseAtt)-idx-1] = att
	}
	return &rv
}

func (s *scenario) Extend(ctx context.Context, pred PredicateFunc, lr *engine.LookupResult) (*scenario, string) {
	newscenario := &scenario{
		parent:  s,
		thisAtt: lr,
	}
	if !lr.Validity.Valid {
		return nil, "attestion invalid"
	}
	if lr.Attestation.DecryptedBody == nil {
		return nil, "attestation is not decrypted"
	}
	pol, err := iapi.PolicySchemeInstanceFor(&lr.Attestation.DecryptedBody.VerifierBody.Policy)
	if err != nil {
		panic(err)
	}
	rtpol, ok := pol.(*iapi.RTreePolicy)
	if !ok {
		return nil, "attestation does not have an RTree policy"
	}
	err = rtpol.CheckValid()
	if err != nil {
		return nil, "attestation policy is invalid"
	}
	if s == nil {
		newscenario.policy = rtpol
	} else {
		interpol, okay, msg, err := rtpol.Intersect(s.policy)
		if err != nil {
			panic(err)
		}
		if !okay {
			return nil, msg
		}
		newscenario.policy = interpol
	}
	weight, msg := pred(ctx, newscenario.policy)
	if weight <= 0 {
		return nil, "predfail: " + msg
	}
	newscenario.weight = weight
	newscenario.terminal, _ = lr.Attestation.Subject()
	return newscenario, ""
}

//When evaluating a path, return an integer indicating the preference of this path.
// <=0 indicates do not follow the path. >0 indicates the path is preferable. The
//weight can be used to implement fall-back routes that offer some but not all of
//the permissions desired
type PredicateFunc func(ctx context.Context, pol *iapi.RTreePolicy) (weight int, message string)

func NewGenericPredicateFunc(wantSupersetOf *iapi.RTreePolicy) PredicateFunc {
	return func(ctx context.Context, pol *iapi.RTreePolicy) (weight int, message string) {
		if wantSupersetOf.IsSubsetOf(pol) {
			return 100, ""
		}
		return -1, "no match"
	}
}

type Params struct {
	Subject         iapi.HashSchemeInstance
	Engine          *engine.Engine
	PolicyPredicate PredicateFunc
	//Typically the domain authority
	Start        iapi.HashSchemeInstance
	EnableOutput bool
}

func NewRTreeBuilder(ctx context.Context, p *Params) (*RTreeBuilder, error) {
	return &RTreeBuilder{
		eng:           p.Engine,
		pred:          p.PolicyPredicate,
		ctx:           ctx,
		outputEnabled: p.EnableOutput,
		subject:       p.Subject,
		start:         p.Start,
	}, nil
}

func (tb *RTreeBuilder) Solutions() []*Solution {
	rv := []*Solution{}
	for _, sol := range tb.solutions {
		rv = append(rv, sol.ToSolution())
	}
	return rv
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
	fmt.Printf("tb A\n")
	//Add the initial scenarios
	lr, le := tb.eng.LookupAttestationsFrom(tb.ctx, tb.start, &iapi.LookupFromFilter{
		Valid: iapi.Bool(true),
	})
	fmt.Printf("tb B\n")
nextAttestation:
	for lres := range lr {
		fmt.Printf("tb C\n")
		var s *scenario
		newScenario, msg := s.Extend(tb.ctx, tb.pred, lres)
		if newScenario == nil {
			tb.wout("skipping %s: %s", lres.Attestation.Keccak256HI().MultihashString(), msg)
			fmt.Printf("tb D\n")
			continue nextAttestation
		}
		//Check if this scenario is a solution or a new scenario
		if iapi.HashSchemeInstanceEqual(tb.subject, newScenario.terminal) {
			fmt.Printf("tb E\n")
			tb.solutions = append(tb.solutions, newScenario)
		} else {
			fmt.Printf("tb F\n")
			tb.scenarios = append(tb.scenarios, newScenario)
		}
	}
	fmt.Printf("tb Gi\n")
	if e := <-le; e != nil {
		panic(e)
	}
	fmt.Printf("tb Gii\n")
	//Now we have our initial scenarios, keep iterating while we have
	//scenarios left
	for len(tb.scenarios) > 0 {
		fmt.Printf("tb G\n")
		err := tb.iterate()
		if err != nil {
			panic(err)
		}
	}

	tb.wout("build complete: %d solutions", len(tb.solutions))
	fmt.Printf("build completed\n")
}

func (tb *RTreeBuilder) iterate() error {
	fmt.Printf("iterate called\n")
	if e := tb.ctx.Err(); e != nil {
		return e
	}
	//Find the maximum weight
	max := 0
	for _, s := range tb.scenarios {
		if s.weight > max {
			max = s.weight
		}
	}

	//Extend all the scenarios equal to the max weight
	replacementscenarios := []*scenario{}
	for _, s := range tb.scenarios {
		if e := tb.ctx.Err(); e != nil {
			return e
		}
		if s.weight < max {
			fmt.Printf("tb AA\n")
			replacementscenarios = append(replacementscenarios, s)
			continue
		}
		fmt.Printf("tb BB\n")
		lr, le := tb.eng.LookupAttestationsFrom(tb.ctx, s.terminal, &iapi.LookupFromFilter{
			Valid: iapi.Bool(true),
		})
	nextAttestation:
		for lres := range lr {
			fmt.Printf("tb CC\n")
			//First check this subject does not appear in the scenario's history
			subj, _ := lres.Attestation.Subject()
			parent := s
			for parent != nil {
				if iapi.HashSchemeInstanceEqual(parent.terminal, subj) {
					continue nextAttestation
				}
				parent = parent.parent
			}
			//Ok we are good, lets create a new scenario
			newScenario, msg := s.Extend(tb.ctx, tb.pred, lres)
			fmt.Printf("tb DD\n")
			if newScenario == nil {
				tb.wout("skipping %s: %s", lres.Attestation.Keccak256HI().MultihashString(), msg)
				continue nextAttestation
			}
			//Check if this scenario is a solution or a new scenario
			if iapi.HashSchemeInstanceEqual(tb.subject, newScenario.terminal) {
				tb.solutions = append(tb.solutions, newScenario)
			} else {
				replacementscenarios = append(replacementscenarios, newScenario)
			}
		}
		if e := <-le; e != nil {
			panic(e)
		}
	}
	fmt.Printf("setting scenarios to:\n")
	spew.Dump(replacementscenarios)
	tb.scenarios = replacementscenarios
	return nil
}
