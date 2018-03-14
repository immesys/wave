package ipfs

import (
	"context"
	"encoding/base64"
	"strings"

	api "github.com/gtfierro/go-ipfs-api"
	"github.com/immesys/wave/iapi"
	"github.com/pkg/errors"
	"gx/ipfs/QmZyZDi491cCNTLfAhwcaDii2Kg4pwKRkhqQzURGDvY6ua/go-multihash"
	cid "gx/ipfs/QmcZfnkapfECQGcLZaf9B79NRg7cRa9EnZh4LSbkCzwNvY/go-cid"
)

// IPFS Storage provider runs as a supplementary daemon to the IPFS daemon
type IPFSStorageProvider struct {
	client        *api.Shell
	block_options map[string]string
	publish       bool
}

// This initializes the IPFS storage provider by establishing a connection with the IPFS daemon API
// (https://ipfs.io/docs/api/). The configuration expects the following options:
//   - ipfs_daemon: HTTP endpoint of IPFS daemon API. Should be set to http://localhost:5001 unless you have altered the IPFS configuration
//   - publish: push objects to subscribed supernodes. Set to "true" or "false" (need to be strings). If you plan on running a supernode, then
//		you should set this to "false"
func (ipfs *IPFSStorageProvider) Initialize(ctx context.Context, config map[string]string) (err error) {
	ipfs.block_options = map[string]string{
		"mhtype": "keccak-256",
		"mhlen":  "32",
		"format": "raw",
	}

	addr, found := config["ipfs_daemon"]
	if !found {
		return errors.New("Config needs 'ipfs_daemon' defined and pointing to the IPFS API endpoint")
	}
	publish, found := config["publish"]
	if !found {
		return errors.New("Config needs 'publish' defined")
	}
	ipfs.publish = strings.ToLower(publish) == "true"
	ipfs.client = api.NewShell(addr)
	if !ipfs.client.IsUp() {
		return errors.Errorf("Cannot connect to IPFS API at %s", addr)
	}

	return nil
}

// Returns the operational status of the IPFS storage provider by checking to see if the IPFS daemon is still up and running.
// Does not currently return anything in the 'info' map
func (ipfs *IPFSStorageProvider) Status(ctx context.Context) (operational bool, info map[string]string, err error) {
	if !ipfs.client.IsUp() {
		operational = false
		return
	}
	operational = true
	return
}

// Inserts a byte array into IPFS and returns the keccak-256 hash (as a WAVE HashSchemeInstance)
func (ipfs *IPFSStorageProvider) Put(ctx context.Context, content []byte) (hash iapi.HashSchemeInstance, err error) {
	cid_string, err := ipfs.client.BlockPut(content, ipfs.block_options)
	bcid, err := cid.Decode(cid_string)
	if err != nil {
		err = errors.Wrapf(err, "Could not decode cid_string %s", cid_string)
		return
	}
	// need to pull the hash of the object out of all the onion-like layers of IPFS structures
	mh := bcid.Hash()
	obj, err := multihash.Decode(mh)
	if err != nil {
		err = errors.Wrapf(err, "Invalid multihash")
		return
	}

	hash = &iapi.HashSchemeInstance_Keccak_256{Val: obj.Digest}

	// pubsub notify!
	// WARNING: if you are operating as a pinning service, then if you set ipfs.publish to true (via the config flag)
	// then you will end up endlessly publishing to yourself.
	if ipfs.publish {
		err = ipfs.client.PubSubPublish("/bw3/storage", base64.URLEncoding.EncodeToString(content))
		if err != nil {
			err = errors.Wrap(err, "Could not pubsub object")
			return
		}
	}

	return
}

// retrieves the byte array associated with the given hash. RIGHT NOW we assume that the hash is keccak-256.
func (ipfs *IPFSStorageProvider) Get(ctx context.Context, hash iapi.HashSchemeInstance) (content []byte, err error) {
	mh, err := multihash.Encode(hash.Value(), multihash.KECCAK_256)
	if err != nil {
		err = errors.Wrapf(err, "Could not encode hash %s", hash.Value())
	}
	bcid := cid.NewCidV1(cid.Raw, mh)
	if err != nil {
		err = errors.Wrapf(err, "Could not encode cid %s", mh)
	}

	content, err = ipfs.client.BlockGet(bcid.String())
	if err != nil {
		err = errors.Wrapf(err, "Could not get hash %s", hash.Value())
	}
	return
}

// not implemented for now
func (ipfs *IPFSStorageProvider) Enqueue(ctx context.Context, queueId iapi.HashSchemeInstance, object iapi.HashSchemeInstance) error {
	return iapi.ErrNotImplemented
}

// not implemented for now
func (ipfs *IPFSStorageProvider) IterateQueue(ctx context.Context, queueId iapi.HashSchemeInstance, iteratorToken string) (object iapi.HashSchemeInstance, nextToken string, err error) {
	err = iapi.ErrNotImplemented
	return
}

// TODO: not sure how to implement this for now
func (ipfs *IPFSStorageProvider) Location(context.Context) iapi.LocationSchemeInstance {
	//SimpleHTTP is version 1
	return iapi.NewLocationSchemeInstanceURL("nada", 1)
}
