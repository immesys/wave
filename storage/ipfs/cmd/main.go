package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/pkg/errors"
	"github.com/urfave/cli"

	api "github.com/gtfierro/go-ipfs-api"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/storage/ipfs"
)

func runPinService(c *cli.Context) error {
	ctx := context.TODO()

	// make sure we set "publish" to false or else we'll hit an infinite publish/subscribe loop
	cfg := map[string]string{
		"ipfs_daemon": c.String("ipfs-daemon"),
		"publish":     "false",
	}
	var provider = new(ipfs.IPFSStorageProvider)
	if err := provider.Initialize(ctx, cfg); err != nil {
		panic(err)
	}

	operational, _, err := provider.Status(ctx)
	if err != nil || !operational {
		return errors.Wrap(err, "IPFS daemon is not available")
	}

	client := api.NewShell(c.String("ipfs-daemon"))
	if !client.IsUp() {
		return errors.Errorf("Cannot connect to IPFS API at %s", c.String("ipfs-daemon"))
	}
	log.Printf("Connected to IPFS API at %s", c.String("ipfs-daemon"))

	subscription, err := client.PubSubSubscribe("/bw3/storage")
	if err != nil {
		return errors.Wrap(err, "Could not subscribe")
	}

	for {
		record, err := subscription.Next()
		if err != nil {
			log.Println(errors.Wrap(err, "Could not get subscription"))
			continue
		}
		data := record.Data()
		hash, err := provider.Put(ctx, data)
		if err != nil {
			log.Println(errors.Wrap(err, "Could not PUT data"))
			continue
		}
		log.Println("PUT", base64.URLEncoding.EncodeToString(hash.Value()))
	}

	select {} // block

	return nil
}

func addFile(c *cli.Context) error {
	ctx := context.TODO()
	if c.NArg() == 0 {
		return errors.New("Need to provide a path to the file to add")
	}

	cfg := map[string]string{
		"ipfs_daemon": c.String("ipfs-daemon"),
		"publish":     "true",
	}
	var provider = new(ipfs.IPFSStorageProvider)
	if err := provider.Initialize(ctx, cfg); err != nil {
		return errors.Wrap(err, "IPFS daemon is not available")
	}

	operational, _, err := provider.Status(ctx)
	if err != nil || !operational {
		return errors.Wrap(err, "IPFS daemon is not available")
	}

	filename := c.Args().Get(0)
	fmt.Println("Adding file", filename)
	file, err := os.Open(filename)
	if err != nil {
		panic(errors.Wrapf(err, "Could not open file %s", filename))
	}
	contents, err := ioutil.ReadAll(file)
	if err != nil {
		panic(errors.Wrapf(err, "Could not read file %s", filename))
	}

	hash, err := provider.Put(ctx, contents)
	if err != nil {
		panic(err)
	}
	fmt.Println(base64.URLEncoding.EncodeToString(hash.Value()))
	return nil
}

func getFile(c *cli.Context) error {
	ctx := context.TODO()
	if c.NArg() == 0 {
		return errors.New("Need to provide the hash you want to retrieve")
	}

	cfg := map[string]string{
		"ipfs_daemon": c.String("ipfs-daemon"),
		"publish":     "false",
	}
	var provider = new(ipfs.IPFSStorageProvider)
	if err := provider.Initialize(ctx, cfg); err != nil {
		return errors.Wrap(err, "IPFS daemon is not available")
	}

	operational, _, err := provider.Status(ctx)
	if err != nil || !operational {
		return errors.Wrap(err, "IPFS daemon is not available")
	}

	b, err := base64.URLEncoding.DecodeString(c.Args().Get(0))
	if err != nil {
		return errors.Wrapf(err, "Could not decode provided hash %s. Is it base64 encoded?", c.Args().Get(0))
	}
	fmt.Println(b)
	hash := &iapi.HashSchemeInstance_Keccak_256{Val: b}

	fmt.Printf("Fetching hash %s\n", c.Args().Get(0))
	content, err := provider.Get(ctx, hash)
	if err != nil {
		return errors.Wrapf(err, "Could not retrieve hash %s", c.Args().Get(0))
	}

	fmt.Println(string(content))

	return nil
}

func main() {
	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:   "pinservice",
			Usage:  "Listen for files and pin them",
			Action: runPinService,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "ipfs-daemon",
					Usage: "HTTP URL of IPFS local API",
					Value: "http://127.0.0.1:5001",
				},
			},
		},
		{
			Name:   "add",
			Usage:  "Add file object and get hash",
			Action: addFile,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "ipfs-daemon",
					Usage: "HTTP URL of IPFS local API",
					Value: "http://127.0.0.1:5001",
				},
			},
		},
		{
			Name:   "get",
			Usage:  "Get file object from hash",
			Action: getFile,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "ipfs-daemon",
					Usage: "HTTP URL of IPFS local API",
					Value: "http://127.0.0.1:5001",
				},
			},
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
