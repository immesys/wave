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
