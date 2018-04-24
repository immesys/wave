package waved

import (
	"fmt"
	"os"
	"time"

	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/iapi"
	"github.com/immesys/wave/localdb/lls"
	"github.com/immesys/wave/localdb/poc"
	"github.com/immesys/wave/storage/overlay"
	"github.com/urfave/cli"
)

const VersionFlag = "Prerelease 0.1.0"

func Main(args []string) {
	app := cli.NewApp()
	app.Name = "waved"
	app.Usage = "Run a WAVE daemon"
	app.Action = action
	app.Version = VersionFlag
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/wave/wave.toml",
		},
	}
	app.Run(args)
}

func action(c *cli.Context) error {
	conf, err := ParseConfig(c.String("config"))
	if err != nil {
		fmt.Printf("could not parse config file: %v", err)
		os.Exit(1)
	}
	MainWithConfig(conf)
	return nil
}

func MainWithConfig(c *Configuration) {
	llsdb, err := lls.NewLowLevelStorage(c.Database)
	if err != nil {
		fmt.Printf("state database error: %v\n", err)
		os.Exit(1)
	}

	si, err := overlay.NewOverlay(c.Storage)
	if err != nil {
		fmt.Printf("storage overlay error: %v\n", err)
		os.Exit(1)
	}

	iapi.InjectStorageInterface(si)

	ws := poc.NewPOC(llsdb)
	api := eapi.NewEAPI(ws)
	api.StartServer(c.ListenIP, c.HTTPListenIP)
	fmt.Printf("server started on %s\n", c.ListenIP)
	for {
		time.Sleep(10 * time.Second)
	}
}
