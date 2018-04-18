package main

import (
	"fmt"
	"testing"
)

func TestRTreeSimpleExisting(t *testing.T) {
	tg := TG()
	tg.Edge(t, "ns", "a", "1", 1)
	tg.BuildCompare(t, "a", "1", 1, 1)
}

func TGraph(t *testing.T, outdegree int, depth int) {
	tg := TG()
	last_tier := []string{"ns"}
	idx := 0
	for d := 0; d < depth; d++ {
		next_tier := []string{}
		for _, lt := range last_tier {
			for od := 0; od < outdegree; od++ {
				nt := fmt.Sprintf("%d", idx)
				idx++
				next_tier = append(next_tier, nt)
				tg.Edge(t, lt, nt, "1", 100)
			}
		}
		last_tier = next_tier
	}
	//Graph built
	tg.BuildCompare(t, last_tier[0], "1", depth, 101-depth)
}

func TestDepth5x1(t *testing.T) {
	TGraph(t, 5, 1)
}

func TestDepth5x5(t *testing.T) {
	TGraph(t, 5, 5)
}

func TestDepth1x5(t *testing.T) {
	TGraph(t, 1, 5)
}

func TestDepth1x10(t *testing.T) {
	TGraph(t, 1, 10)
}

func TestDepth1x15(t *testing.T) {
	TGraph(t, 1, 15)
}

func TestDepth1x20(t *testing.T) {
	TGraph(t, 1, 20)
}
