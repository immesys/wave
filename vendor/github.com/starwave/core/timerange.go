package core

import (
	"bytes"
	"time"
)

func TimeRangeFromPathsSingleLevel(prefix TimePath, startQuantity uint16, endQuantity uint16) []TimePath {
	if len(prefix) > MaxTimeLength {
		panic("prefix too long")
	}

	if endQuantity < startQuantity {
		panic("endQuantity is less than startQuantity")
	}

	ids := make([]TimePath, 0, endQuantity-startQuantity+1)

	newComponentIndex := TimeComponentPosition(len(prefix))
	for q := startQuantity; q <= endQuantity; q++ {
		id := make(TimePath, 0, len(prefix))
		id = append(id, prefix...)
		id = append(id, NewTimeComponent(q, newComponentIndex))
		ids = append(ids, id)
	}

	return ids
}

// TimeRangeFromPaths is a function that returns all time paths such that
// STARTPATH <= path <= ENDPATH. Useful for computing which keys to grant
// for expiry. STARTPATH and ENDPATH are fully-qualified paths.
func TimeRangeFromPaths(startPath TimePath, endPath TimePath) []TimePath {
	if len(startPath) != MaxTimeLength || len(endPath) != MaxTimeLength {
		panic("startPath and endPath must be fully qualified")
	}

	/* Copy startPath and endPath so we can mutate them. */
	start := make(TimePath, 0, len(startPath))
	start = append(start, startPath...)
	end := make(TimePath, 0, len(endPath))
	end = append(end, endPath...)

	firstDifferingIndex := len(start)
	for i := range startPath {
		if !bytes.Equal(start[i].Representation(), end[i].Representation()) {
			firstDifferingIndex = i
			break
		} else if start[i].Quantity() > end[i].Quantity() {
			panic("endPath is before startPath")
		}
	}

	if firstDifferingIndex == len(start) {
		return []TimePath{start}
	}

	ids := make([]TimePath, 0, 8)

	var i int

	fullStart := true
	i = MaxTimeLength - 1
	for i > firstDifferingIndex {
		min, max := TimeComponentBounds(start[:i], TimeComponentPosition(i))
		quantity := start[i].Quantity()
		if quantity == min {
			i--
		} else {
			fullStart = false
			filler := TimeRangeFromPathsSingleLevel(start[:i], quantity, max)
			ids = append(ids, filler...)

			/*
			 * Implicitly, this completes the current layer of the tree, meaning
			 * we have to increment the parent. For example, if this grants the
			 * remaining hours in a day, the parent now needs to be the _next_
			 * day, since we have granted all of the keys for this day.
			 */
			var j int
			for j = i - 1; j > firstDifferingIndex; j-- {
				min, max := TimeComponentBounds(start[:j], TimeComponentPosition(j))
				quantity := start[j].Quantity()
				if quantity == max {
					start[j] = NewTimeComponent(min, TimeComponentPosition(j))
				} else {
					start[j] = NewTimeComponent(quantity+1, TimeComponentPosition(j))
					break
				}
			}
			i = j
		}
	}

	/*
	 * Handle the first differing component (i.e., the top layer).
	 *
	 * An important edge case is: if the start path has "min" and the end path
	 * has "max", we should include the parent of the first differing component,
	 * rather than the entire layer at the first differing component.
	 */

	singleNodeAtTopLevel := false
	startQuantity := start[firstDifferingIndex].Quantity()
	endQuantity := end[firstDifferingIndex].Quantity()
	min, max := TimeComponentBounds(start[:firstDifferingIndex], TimeComponentPosition(firstDifferingIndex))
	if firstDifferingIndex != 0 && startQuantity == min && endQuantity == max {
		singleNodeAtTopLevel = true
		ids = append(ids, start[:firstDifferingIndex])
	} else {
		if fullStart {
			ids = append(ids, start[:firstDifferingIndex+1])
		}
		if endQuantity > startQuantity+1 {
			topLevel := TimeRangeFromPathsSingleLevel(start[:firstDifferingIndex], startQuantity+1, endQuantity-1)
			ids = append(ids, topLevel...)
		}
	}

	/* Now, we need to figure out how much of the last component to include. */

	/*
	 * We still work from leaf up, so we need this buffer to reorder the
	 * results to be in increasing order.
	 */
	endBuffer := make([][]TimePath, 0, MaxTimeLength)

	fullEnd := true
	i = MaxTimeLength - 1
	for i > firstDifferingIndex {
		min, max := TimeComponentBounds(end[:i], TimeComponentPosition(i))
		quantity := end[i].Quantity()
		if quantity == max {
			i--
		} else {
			fullEnd = false
			filler := TimeRangeFromPathsSingleLevel(end[:i], min, quantity)
			endBuffer = append(endBuffer, filler)

			/*
			 * Like before, we need to adjust the parent to account for the
			 * fact that we have completed a time component.
			 */
			var j int
			for j = i - 1; j >= 0; j-- {
				min, max := TimeComponentBounds(end[:j], TimeComponentPosition(j))
				quantity := end[j].Quantity()
				if quantity == min {
					end[j] = NewTimeComponent(max, TimeComponentPosition(j))
				} else {
					end[j] = NewTimeComponent(quantity-1, TimeComponentPosition(j))
					break
				}
			}
			i = j
		}
	}

	for k := len(endBuffer) - 1; k >= 0; k-- {
		ids = append(ids, endBuffer[k]...)
	}

	if !singleNodeAtTopLevel && fullEnd {
		ids = append(ids, end[:firstDifferingIndex+1])
	}

	return ids
}

func TimeRange(start time.Time, end time.Time) ([]TimePath, error) {
	startPath, err := ParseTime(start)
	if err != nil {
		return nil, err
	}
	endPath, err := ParseTime(end)
	if err != nil {
		return nil, err
	}
	return TimeRangeFromPaths(startPath, endPath), nil
}
