package iapi

import "time"

func String(s string) *string {
	return &s
}
func Bool(b bool) *bool {
	return &b
}
func Int(i int) *int {
	return &i
}
func Time(t time.Time) *time.Time {
	return &t
}
func Partition(s ...string) [][]byte {
	rv := [][]byte{}
	for _, i := range s {
		rv = append(rv, []byte(i))
	}
	return rv
}
func Partition20(s ...string) [][]byte {
	rv := make([][]byte, 20)
	for idx, i := range s {
		rv[idx] = []byte(i)
	}
	return rv
}
