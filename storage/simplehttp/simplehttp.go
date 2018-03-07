package simplehttp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/immesys/wave/iapi"
)

var _ iapi.StorageDriverInterface = &SimpleHTTPStorage{}

type PutObjectRequest struct {
	DER []byte `json:"der"`
}
type PutObjectResponse struct {
	HashScheme string `json:"hashScheme"`
	Hash       []byte `json:"hash"`
}
type ObjectResponse struct {
	DER []byte `json:"der"`
}
type NoSuchObjectResponse struct {
}
type IterateQueueResponse struct {
	HashScheme string `json:"hashScheme"`
	Hash       []byte `json:"hash"`
	NextToken  string `json:"nextToken"`
}
type EnqueueResponse struct {
}
type NoSuchQueueEntryResponse struct {
}
type EnqueueRequest struct {
	IdHashScheme    string `json:"idHashScheme"`
	EntryHashScheme string `json:"entryHashScheme"`
	EntryHash       []byte `json:"entryHash"`
}

type SimpleHTTPStorage struct {
	url string
}

func (s *SimpleHTTPStorage) Location(context.Context) iapi.LocationSchemeInstance {
	//SimpleHTTP is version 1
	return iapi.NewLocationSchemeInstanceURL(s.url, 1)
}

func (s *SimpleHTTPStorage) PreferredHashScheme() iapi.HashScheme {
	//TODO
	return iapi.KECCAK256
}
func (s *SimpleHTTPStorage) Initialize(ctx context.Context, name string, config map[string]string) error {
	url, ok := config["url"]
	if !ok {
		return fmt.Errorf("the 'url' config option is mandatory")
	}
	s.url = url
	return nil
}

func (s *SimpleHTTPStorage) Status(ctx context.Context) (operational bool, info map[string]string, err error) {
	return true, make(map[string]string), nil
}

func (s *SimpleHTTPStorage) Put(ctx context.Context, content []byte) (iapi.HashSchemeInstance, error) {
	buf := bytes.Buffer{}
	putRequest := &PutObjectRequest{
		DER: content,
	}
	enc := json.NewEncoder(&buf)
	err := enc.Encode(putRequest)
	if err != nil {
		return nil, err
	}
	resp, err := http.Post(fmt.Sprintf("%s/obj", s.url), "application/json", &buf)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		return nil, fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	rv := &PutObjectResponse{}
	err = json.Unmarshal(body, rv)
	if err != nil {
		return nil, err
	}
	if len(rv.Hash) != 32 {
		return nil, fmt.Errorf("Remote sent invalid hash")
	}
	//Lazily check that the hash is keccak256
	if rv.HashScheme != iapi.KECCAK256.OID().String() {
		return nil, fmt.Errorf("Remote sent unsupported hash scheme")
	}
	hi := &iapi.HashSchemeInstance_Keccak_256{Val: rv.Hash}
	return hi, nil
}

func (s *SimpleHTTPStorage) Get(ctx context.Context, hash iapi.HashSchemeInstance) (content []byte, err error) {
	b64 := base64.URLEncoding.EncodeToString(hash.Value())
	resp, err := http.Get(fmt.Sprintf("%s/obj/%s?scheme=%s", s.url, b64, hash.OID().String()))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	rv := &ObjectResponse{}
	err = json.Unmarshal(body, rv)
	if err != nil {
		return nil, err
	}
	return rv.DER, nil
}

func (s *SimpleHTTPStorage) Enqueue(ctx context.Context, queueId iapi.HashSchemeInstance, object iapi.HashSchemeInstance) error {
	buf := bytes.Buffer{}
	queueRequest := &EnqueueRequest{
		IdHashScheme:    queueId.OID().String(),
		EntryHashScheme: object.OID().String(),
		EntryHash:       object.Value(),
	}
	err := json.NewEncoder(&buf).Encode(queueRequest)
	if err != nil {
		panic(err)
	}
	b64 := base64.URLEncoding.EncodeToString(queueId.Value())
	resp, err := http.Post(fmt.Sprintf("%s/queue/%s", s.url, b64), "application/json", &buf)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		return fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	return nil
}

func (s *SimpleHTTPStorage) IterateQueue(ctx context.Context, queueId iapi.HashSchemeInstance, iteratorToken string) (object iapi.HashSchemeInstance, nextToken string, err error) {
	b64 := base64.URLEncoding.EncodeToString(queueId.Value())
	resp, err := http.Get(fmt.Sprintf("%s/queue/%s?scheme=%s&token=%s", s.url, b64, queueId.OID().String(), iteratorToken))
	if err != nil {
		return nil, "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, "", iapi.ErrNoMore
	}
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	iterR := &IterateQueueResponse{}
	err = json.Unmarshal(body, iterR)
	if err != nil {
		return nil, "", fmt.Errorf("Remote sent invalid response")
	}
	if iterR.HashScheme != iapi.KECCAK256.OID().String() {
		return nil, "", fmt.Errorf("Remote sent unsupported hash scheme")
	}
	hi := &iapi.HashSchemeInstance_Keccak_256{Val: iterR.Hash}
	return hi, iterR.NextToken, nil
}
