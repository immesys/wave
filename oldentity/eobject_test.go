package entity

import (
	"encoding/base64"
	"io/ioutil"
	"testing"
)

func ToB64(arr []byte) string {
	return base64.URLEncoding.EncodeToString(arr)
}

func TestMsgp(t *testing.T) {
	e := NewEntity()
	blob, err := e.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	ioutil.WriteFile("out.mp", blob, 0777)
	//fmt.Printf("serialized: %x", blob)
	res := &Entity{}
	_, err = res.UnmarshalMsg(blob)
	if err != nil {
		t.Fatal(err)
	}
}
