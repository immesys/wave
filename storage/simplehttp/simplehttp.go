package simplehttp

import (
	"bytes"
	"context"
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
	Hash           []byte `json:"hash"`
	V1SMR          []byte `json:"v1smr"`
	V1MapInclusion []byte `json:"v1inclusion"`
}
type InfoResponse struct {
	HashScheme string `json:"hashScheme"`
	Version    string `json:"version"`
}
type ObjectResponse struct {
	DER            []byte `json:"der"`
	V1SMR          []byte `json:"v1smr"`
	V1MapInclusion []byte `json:"v1inclusion"`
}
type NoSuchObjectResponse struct {
}
type IterateQueueResponse struct {
	Hash           []byte `json:"hash"`
	NextToken      string `json:"nextToken"`
	V1SMR          []byte `json:"v1smr"`
	V1MapInclusion []byte `json:"v1inclusion"`
}
type EnqueueResponse struct {
	V1SMR          []byte `json:"v1smr"`
	V1MapInclusion []byte `json:"v1inclusion"`
}
type NoSuchQueueEntryResponse struct {
}
type EnqueueRequest struct {
	EntryHash []byte `json:"entryHash"`
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
	//Lazily check that the hash is keccak256
	hi := iapi.HashSchemeInstanceFromMultihash(rv.Hash)
	if !hi.Supported() {
		return nil, fmt.Errorf("remote sent invalid hash")
	}
	return hi, nil
}

func (s *SimpleHTTPStorage) Get(ctx context.Context, hash iapi.HashSchemeInstance) (content []byte, err error) {
	b64 := hash.MultihashString()
	resp, err := http.Get(fmt.Sprintf("%s/obj/%s", s.url, b64))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, iapi.ErrObjectNotFound
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
		EntryHash: object.Multihash(),
	}
	err := json.NewEncoder(&buf).Encode(queueRequest)
	if err != nil {
		panic(err)
	}
	b64 := queueId.MultihashString()
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
	b64 := queueId.MultihashString()
	resp, err := http.Get(fmt.Sprintf("%s/queue/%s?token=%s", s.url, b64, iteratorToken))
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
	hi := iapi.HashSchemeInstanceFromMultihash(iterR.Hash)
	return hi, iterR.NextToken, nil
}
