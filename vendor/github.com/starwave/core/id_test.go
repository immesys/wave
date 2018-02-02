package core

import (
	"bytes"
	"testing"
	"time"
)

func TestURIMarshal(t *testing.T) {
	uripath, err := ParseURI("a/b/c/*")
	if err != nil {
		t.Fatal(err)
	}

	marshalled := URIToBytes(uripath)
	unmarshalled := URIFromBytes(marshalled)

	if len(uripath) != len(unmarshalled) {
		t.Fatal("Unmarshalled URI is different length from original URI")
	}

	for i, comp := range uripath {
		ucomp := unmarshalled[i]

		if !bytes.Equal(comp, ucomp) {
			t.Fatalf("Component %d differs from unmarshalled URI and original URI", i)
		}
	}
}

func TestTimeMarshal(t *testing.T) {
	timepath, err := ParseTime(time.Now())
	if err != nil {
		t.Fatal(err)
	}

	marshalled := TimeToBytes(timepath)
	unmarshalled := TimeFromBytes(marshalled)

	if len(timepath) != len(unmarshalled) {
		t.Fatal("Unmarshalled Time is different length from original Time")
	}

	for i, comp := range timepath {
		ucomp := unmarshalled[i]

		if !bytes.Equal(comp, ucomp) {
			t.Fatalf("Component %d differs from unmarshalled Time and original Time", i)
		}
	}
}
