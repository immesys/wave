package iapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/immesys/wave/serdes"
	"github.com/immesys/wave/wve"
)

func CalculateWR1Partition(validFrom time.Time, validUntil time.Time, userPrefix [][]byte) ([][]byte, wve.WVE) {
	if len(userPrefix) != 12 {
		return nil, wve.Err(wve.InvalidParameter, "user prefix partition must be 12 elements")
	}
	tiers := WR1PartitionTiers
	endNS := validUntil.UnixNano()
	endNS -= endNS % tiers[3]
	endNS += tiers[3]
	startNS := validFrom.UnixNano()
	startNS -= startNS % tiers[3]

	intstart := make([]int64, 4)
	intend := make([]int64, 4)
	bytestart := make([][]byte, 4)
	byteend := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		intstart[i] = startNS / tiers[i]
		intend[i] = endNS / tiers[i]
		bytestart[i] = make([]byte, 2)
		binary.BigEndian.PutUint16(bytestart[i], uint16(intstart[i]))
		byteend[i] = make([]byte, 2)
		binary.BigEndian.PutUint16(byteend[i], uint16(intend[i]))
	}
	rv := make([][]byte, 20)
	copy(rv[:12], userPrefix)
	for i := 0; i < 4; i++ {
		rv[12+i] = bytestart[i]
		rv[16+i] = byteend[i]
	}
	return rv, nil
}

//This generates the partitions and calculates the differences to generate the keyring bundle entries, but it does not generate the keys
func CalculateEmptyKeyBundleEntries(startDat time.Time, endDat time.Time, userPrefix [][]byte) ([][][]byte, []serdes.KeyringBundleEntry, wve.WVE) {
	partitions, err := CalculateKeyBundlePartitions(startDat, endDat, userPrefix)
	if err != nil {
		return nil, nil, err
	}

	rv := make([]serdes.KeyringBundleEntry, len(partitions))
	current := make([][]byte, 20)
	for i := 0; i < len(partitions); i++ {
		for idx, p := range partitions[i] {
			//Add all the changes
			if !bytes.Equal(p, current[idx]) {
				cp := make([]byte, len(p))
				copy(cp[:], p[:])
				rv[i].PartitionChange = append(rv[i].PartitionChange, serdes.PartitionChange{
					Index:   idx,
					Content: cp,
				})
				current[idx] = cp
			}
			//Move on to the next partition
		}
	}

	return partitions, rv, nil
}

func DecodeKeyBundleEntries(be []serdes.KeyringBundleEntry) ([][][]byte, wve.WVE) {
	rv := make([][][]byte, len(be))
	current := make([][]byte, 20)
	for i := 0; i < len(rv); i++ {
		for _, change := range be[i].PartitionChange {
			if change.Index > 20 {
				return nil, wve.Err(wve.MalformedObject, "bad partition change record")
			}
			current[change.Index] = change.Content
		}
		cp := make([][]byte, 20)
		for k := 0; k < 20; k++ {
			if len(current[k]) > 0 {
				cp[k] = current[k]
			}
		}
		rv[i] = cp
	}
	return rv, nil
}

//The WR1 recommended partition scheme is
// <userdefined: 12> <beginrange: 4> <endrange: 4>
// Which allows for expiry ranges at a granularity of weeks
// In the worst case this requires a key bundle of 144 keys
// to delegate. Ranges are only allowed to go up to 3 years
// long.
var WR1PartitionTiers []int64 = []int64{int64(64 * 7 * 24 * time.Hour), int64(16 * 7 * 24 * time.Hour), int64(4 * 7 * 24 * time.Hour), int64(7 * 24 * time.Hour)}

func CalculateKeyBundlePartitions(startDat time.Time, endDat time.Time, userPrefix [][]byte) ([][][]byte, wve.WVE) {
	//round up the end date by a week
	tiers := WR1PartitionTiers
	left := [][]int64{}
	leftTimeRanges := []DateRange{}
	right := [][]int64{}
	rightTimeRanges := []DateRange{}
	_ = left
	_ = right
	//The left side, or beginrange, covers all times that permitted ranges can start in. Therefore it must cover (startDate-3years)..(endDate)
	endNS := endDat.UnixNano()
	endNS -= endNS % tiers[3]
	endNS += tiers[3]
	startNS := startDat.UnixNano()
	startNS -= startNS % tiers[3]

	//First calculate the left
	cursor := startNS - int64(3*365*24*time.Hour)
	cursor -= (cursor % tiers[0])
	current := make([]int64, len(tiers))
	current[0] = cursor / tiers[0]
	tier := 0
	//fmt.Printf("end date is %s\n", time.Unix(0, endNS))
	for cursor < endNS {
		if cursor+tiers[tier] <= endNS {
			//append current
			var sd, ed time.Time
			for lastentry := len(tiers) - 1; lastentry >= 0; lastentry-- {
				if current[lastentry] != 0 {
					sd = time.Unix(0, current[lastentry]*tiers[lastentry])
					ed = time.Unix(0, (current[lastentry]+1)*tiers[lastentry])
					break
				}
			}

			//fmt.Printf("would use %4v %s   ->   %s\n", current, sd, ed)
			cp := make([]int64, len(current))
			copy(cp[:], current[:])
			left = append(left, cp)
			leftTimeRanges = append(leftTimeRanges, DateRange{sd, ed})
			cursor += tiers[tier]
			current[tier] = cursor / tiers[tier]
		} else {
			tier++
			if tier < len(tiers) {
				current[tier] = cursor / tiers[tier]
			}
		}
		if tier == len(tiers) {
			break
		}
	}

	cursor = endNS + int64(3*365*24*time.Hour)
	cursor -= cursor % tiers[0]
	cursor += tiers[0]
	//fmt.Printf("corrected end date for start is %s\n", time.Unix(0, cursor))
	current = make([]int64, len(tiers))
	current[0] = cursor / tiers[0]
	tier = 0
	//fmt.Printf("start date is %s\n", time.Unix(0, startNS))
	for cursor > startNS {
		if cursor-tiers[tier] >= startNS {
			//append current
			var sd, ed time.Time
			for lastentry := len(tiers) - 1; lastentry >= 0; lastentry-- {
				if current[lastentry] != 0 {
					sd = time.Unix(0, (current[lastentry]-1)*tiers[lastentry])
					ed = time.Unix(0, (current[lastentry])*tiers[lastentry])
					break
				}
			}

			cp := make([]int64, len(current))
			for idx, e := range current {
				if e != 0 {
					//switch from end time to start time
					cp[idx] = e - 1
				}
			}
			right = append(right, cp)
			rightTimeRanges = append(rightTimeRanges, DateRange{sd, ed})
			//fmt.Printf("would use %4v %s   ->   %s\n", cp, sd, ed)
			cursor -= tiers[tier]
			current[tier] = cursor / tiers[tier]

		} else {
			tier++
			if tier < len(tiers) {
				current[tier] = cursor / tiers[tier]
			}
		}
		if tier == len(tiers) {
			break
		}
	}

	//Now multiply left and right
	results := make([][][]byte, 0, len(left)*len(right))
	for li := 0; li < len(left); li++ {
		for ri := 0; ri < len(right); ri++ {
			//First check that the right start is not more than three years after
			//the left end. In that case this combination could never be used because
			//attestations can not be longer than 3 years
			if leftTimeRanges[li].End.Add(3 * 365 * 24 * time.Hour).Before(rightTimeRanges[ri].Start) {
				continue
			}

			r := make([][]byte, 20)
			copy(r[:], userPrefix)

			for i := 0; i < 4; i++ {
				var e []byte
				if left[li][i] != 0 {
					e = make([]byte, 2)
					binary.BigEndian.PutUint16(e, uint16(left[li][i]))
				}
				r[12+i] = e
			}

			for i := 0; i < 4; i++ {
				var e []byte
				if right[ri][i] != 0 {
					e = make([]byte, 2)
					binary.BigEndian.PutUint16(e, uint16(right[ri][i]))
				}
				r[16+i] = e
			}

			results = append(results, r)
		}
	}
	return results, nil
}

func WR1PartitionToString(p [][]byte) string {
	tfmt := "2006-01-02 15:04:05"
	result := bytes.Buffer{}
	result.WriteString("[")
	for i := 0; i < 12; i++ {
		if p[i] == nil {
			break
		}
		result.WriteString(fmt.Sprintf("%q/", string(p[i])))
	}
	result.WriteString("] ")
	startRange, startErr := WR1PartitionChunkToDateRange(p[12:16])
	if startErr != nil {
		result.WriteString("(start range invalid) ")
	} else {
		result.WriteString(fmt.Sprintf("(%s -> %s) ",
			startRange.Start.Format(tfmt),
			startRange.End.Format(tfmt)))
	}
	endRange, endErr := WR1PartitionChunkToDateRange(p[16:])
	if endErr != nil {
		result.WriteString("(end range invalid)")
	} else {
		result.WriteString(fmt.Sprintf("(%s -> %s) ",
			endRange.Start.Format(tfmt),
			endRange.End.Format(tfmt)))
	}
	return result.String()
}

type DateRange struct {
	Start time.Time
	End   time.Time
}

func ParseWR1Partition(p [][]byte) (start *DateRange, end *DateRange, user [][]byte, err wve.WVE) {
	startRange, startErr := WR1PartitionChunkToDateRange(p[12:16])
	if startErr != nil {
		return nil, nil, nil, startErr
	}
	endRange, endErr := WR1PartitionChunkToDateRange(p[16:])
	if endErr != nil {
		return nil, nil, nil, endErr
	}
	return startRange, endRange, p[0:12], nil
}
func WR1PartitionChunkToDateRange(chunk [][]byte) (*DateRange, wve.WVE) {
	ichunk := make([]int64, 4)
	for i := 0; i < 4; i++ {
		if len(chunk[i]) == 0 {
			break
		}
		if len(chunk[i]) != 2 {
			return nil, wve.Err(wve.MalformedPartition, "not valid WR1 partition")
		}
		ichunk[i] = int64(binary.BigEndian.Uint16(chunk[i]))
	}
	for i := 3; i >= 0; i-- {
		if ichunk[i] != 0 {
			rv := DateRange{
				Start: time.Unix(0, ichunk[i]*WR1PartitionTiers[i]),
			}
			rv.End = rv.Start.Add(time.Duration(WR1PartitionTiers[i]))
			return &rv, nil
		}
	}
	return nil, wve.Err(wve.MalformedPartition, "not valid WR1 partition")
}
