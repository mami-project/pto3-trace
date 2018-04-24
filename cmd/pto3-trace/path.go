package main

import (
	"strings"

	pto3 "github.com/mami-project/pto3-go"
)

// conversation between @britram and @sten69 on slack:
//
// @sten69: "if change happens between `A` and `B`, then the path is `[S B * D]` if `A` = `S`,
//   `[S A B * D]` if `A` is the first hop, `[S * A B D]` if `B` is the last hop, `[S * A D]`
//   if `B` = `D`, and `[S * A B * D]` otherwise"
// @britram: "yes"
//
// By extension, here is a complete list of cases. Let S and D be the source and destination
// IP addresses, respectively. Assume S != D. Let P = [P0, ..., Pn-1] be an array of intemediate
// nodes, possibly "*". The node for which change is reported has index k (note: 0 <= k <= n; in
// the case k = n, change happens between Pn-1 and D). P may be empty, in which case n == 0.
//
// No Condition          Path
// 1  n = 0              [S D]
// 2  n = 1, k = 0       [S P0 D]
// 3  n = 1, k = 1       [S P0 D] (indistinguishable from previous case, won't happen in interesting cases, says @britram)
// 4  n > 1, k = 0       [S P0 * D]
// 5  n > 1, k = n       [S * Pn-1 D]
// 6  n = 2, k = 1       [S P0 P1 D]
// 7  n > 2, k = 1       [S P0 P1 * D]
// 8  n > 2, k = n-1     [S * Pk-1 Pk D]
// 9  n > 3, 2 <= k < n-1 [S * Pk-1 Pk * D]
//
// Additional rule: adjacent "*"s are collapsed. This can happen if the lower of the Pj is "*"
// and there is already a "*" there (cases n > 2, k = n-1 and n > 3, 1 <= k < n-1).
//
func makePathForChange(old *pto3.Path, source string, tbobs *tbObs, index int) *pto3.Path {
	if old != nil {
		return old
	}

	n := len(tbobs.Hops)
	if n > 0 && tbobs.Hops[n-1].Address == tbobs.Dst {
		n--
	}

	var pathString strings.Builder

	pathString.WriteString(source)

	if n == 1 {
		// case 2, case 3
		pathString.WriteString(" ")
		pathString.WriteString(tbobs.Hops[0].Address)
	} else if n > 1 && index == 0 {
		// case 4
		pathString.WriteString(" ")
		// TODO: panic if tbobs.Hops[1].Address == "*"?
		pathString.WriteString(tbobs.Hops[0].Address)
		pathString.WriteString(" *")
	} else if n > 1 && index == n {
		// case 5
		pathString.WriteString(" *")
		if tbobs.Hops[n-1].Address != "*" {
			pathString.WriteString(" ")
			pathString.WriteString(tbobs.Hops[n-1].Address)
		}
	} else if n == 2 && index == 1 {
		// case 6
		pathString.WriteString(" ")
		pathString.WriteString(tbobs.Hops[0].Address)
		pathString.WriteString(" ")
		pathString.WriteString(tbobs.Hops[1].Address)
	} else if n > 2 && index == 1 {
		// case 7
		pathString.WriteString(" ")
		pathString.WriteString(tbobs.Hops[0].Address)
		pathString.WriteString(" ")
		// TODO: panic if tbobs.Hops[1].Address == "*"?
		pathString.WriteString(tbobs.Hops[1].Address)
		pathString.WriteString(" *")
	} else if n > 2 && index == n-1 {
		// case 8
		pathString.WriteString(" * ")
		if tbobs.Hops[index-1].Address != "*" {
			pathString.WriteString(tbobs.Hops[index-1].Address)
			pathString.WriteString(" ")
		}
		pathString.WriteString(tbobs.Hops[index].Address)
	} else if n > 3 && 2 <= index && index < n-1 {
		// case 9
		pathString.WriteString(" * ")
		if tbobs.Hops[index-1].Address != "*" {
			pathString.WriteString(tbobs.Hops[index-1].Address)
			pathString.WriteString(" ")
		}
		pathString.WriteString(tbobs.Hops[index].Address)
		pathString.WriteString(" *")
	}
	pathString.WriteString(" ")
	pathString.WriteString(tbobs.Dst)

	return pto3.NewPath(pathString.String())
}

func makeFullPath(source string, tbobs *tbObs) *pto3.Path {
	var pathString strings.Builder

	pathString.WriteString(source)

	var printingStars bool
	for _, h := range tbobs.Hops {
		if h.Address != "*" {
			if printingStars {
				pathString.WriteString(" *")
			}
			pathString.WriteString(" ")
			pathString.WriteString(h.Address)
		}
		printingStars = h.Address == "*"
	}

	if printingStars {
		pathString.WriteString(" *")
	}

	if tbobs.Hops[len(tbobs.Hops)-1].Address != tbobs.Dst {
		pathString.WriteString(" ")
		pathString.WriteString(tbobs.Dst)
	}

	return pto3.NewPath(pathString.String())
}
