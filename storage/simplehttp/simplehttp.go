package simplehttp

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/immesys/wave/iapi"
)

var _ iapi.StorageDriverInterface = &SimpleHTTPStorage{}

type QueueResponse struct {
	NextToken string
	Content   []byte
}

type SimpleHTTPStorage struct {
	url string
}

func (s *SimpleHTTPStorage) Location(context.Context) iapi.LocationSchemeInstance {
	return iapi.NewLocationSchemeInstanceURL(s.url, 1)
}

func (s *SimpleHTTPStorage) Initialize(ctx context.Context, config map[string]string) error {
	url, ok := config["url"]
	if !ok {
		return fmt.Errorf("the 'url' config option is mandatory")
	}
	s.url = url
	return nil
}

func (s *SimpleHTTPStorage) Status(ctx context.Context) (operational bool, info map[string]string, err error) {
	panic("ni")
}

func (s *SimpleHTTPStorage) Put(ctx context.Context, content []byte) (iapi.HashSchemeInstance, error) {
	buf := bytes.NewBuffer(content)
	resp, err := http.Post(fmt.Sprintf("%s/obj", s.url), "application/octet-stream", buf)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	hashbin := make([]byte, 32)
	ln, err := hex.Decode(hashbin, body)
	if ln != 32 || err != nil {
		return nil, fmt.Errorf("remote gave a bad hash")
	}
	//Simple HTTP uses keccak256 as the hash
	hi := &iapi.HashSchemeInstance_Keccak_256{Val: hashbin}
	return hi, nil
}

func (s *SimpleHTTPStorage) Get(ctx context.Context, hash iapi.HashSchemeInstance) (content []byte, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/obj/%064x", s.url, hash.Value()))
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	return body, nil
}

func (s *SimpleHTTPStorage) Enqueue(ctx context.Context, queueId iapi.HashSchemeInstance, object iapi.HashSchemeInstance) error {
	buf := bytes.NewBuffer(object.Value())
	resp, err := http.Post(fmt.Sprintf("%s/queue/%064x", s.url, queueId.Value()), "application/octet-stream", buf)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("Remote error: %d (%s)\n", resp.StatusCode, body)
	}
	return nil
}

func (s *SimpleHTTPStorage) IterateQueue(ctx context.Context, queueId iapi.HashSchemeInstance, iteratorToken string) (object iapi.HashSchemeInstance, nextToken string, err error) {
	resp, err := http.Get(fmt.Sprintf("%s/queue/%064x/%s", s.url, queueId.Value(), iteratorToken))
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
	iterR := &QueueResponse{}
	err = json.Unmarshal(body, iterR)
	if err != nil {
		return nil, "", fmt.Errorf("Remote sent invalid response")
	}
	hi := &iapi.HashSchemeInstance_Keccak_256{Val: iterR.Content}
	return hi, iterR.NextToken, nil
}
