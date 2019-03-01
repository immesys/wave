package main

import (
	"os"

	"github.com/urfave/cli"
)

const VersionFlag = "0.4.2"

func main() {
	app := cli.NewApp()
	app.Name = "wv"
	app.Usage = "WAVE command line tool"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "config",
			Value: "/etc/wave/wave.toml",
		},
	}
	app.Version = VersionFlag
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "agent",
			Usage:  "set the wave agent",
			Value:  "127.0.0.1:410",
			EnvVar: "WAVE_AGENT",
		},
	}
	oflag := cli.StringFlag{
		Name:  "outfile, o",
		Usage: "save the result to this file",
	}
	app.Commands = []cli.Command{
		{
			Name:    "listlocations",
			Aliases: []string{"lsloc"},
			Usage:   "list the locations that the agent supports",
			Action:  cli.ActionFunc(actionListLocations),
			Flags:   []cli.Flag{},
		},
		{
			Name:   "resync",
			Usage:  "resynchronize the perspective graph",
			Action: cli.ActionFunc(actionResync),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "perspective",
					Usage:  "the perspective entity secrets",
					EnvVar: "WAVE_DEFAULT_ENTITY",
				},
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "the passphrase to use if required",
				},
			},
		},
		{
			Name:   "revoke",
			Usage:  "revoke an entity/attestation/name declaration",
			Action: cli.ActionFunc(actionRevoke),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "attester",
					EnvVar: "WAVE_DEFAULT_ENTITY",
				},
				cli.StringFlag{
					Name:  "attestation",
					Usage: "an attestation to revoke",
				},
				cli.StringFlag{
					Name:  "entity",
					Usage: "revoke an entity",
				},
				cli.StringFlag{
					Name:  "name",
					Usage: "revoke a name declaration",
				},
			},
		},
		{
			Name:    "mkentity",
			Aliases: []string{"mke"},
			Usage:   "create a new entity",
			Action:  cli.ActionFunc(actionMkEntity),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "expiry, e",
					Value:  "30d",
					Usage:  "set the expiry measured from now e.g. 10d5h10s",
					EnvVar: "WAVE_DEFAULT_EXPIRY",
				},
				cli.StringFlag{
					Name:  "revocationlocation",
					Value: "default",
					Usage: "where will revocations of this entity be located",
				},
				cli.BoolFlag{
					Name:  "nopassphrase",
					Usage: "do not encrypt the entity secrets",
				},
				cli.BoolFlag{
					Name:  "nopublish",
					Usage: "do not publish the entity",
				},

				oflag,
			},
		},
		{
			Name:      "rtprove",
			Usage:     "create an RTree proof",
			Action:    cli.ActionFunc(actionRTProve),
			ArgsUsage: "permset:perm[,perm,perm...]@namespace/resource [permset...]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "subject",
					Usage:  "the subject entity secrets",
					EnvVar: "WAVE_DEFAULT_ENTITY",
				},
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "the passphrase to use if required",
				},
				cli.BoolFlag{
					Name:  "skipsync",
					Usage: "skip graph sync before proving",
				},
				// grant pset:perm,perm,perm@ns/suffix
				oflag,
			},
		},
		{
			Name:      "rtgrant",
			Usage:     "create an RTree attestation",
			Action:    cli.ActionFunc(actionRTGrant),
			ArgsUsage: "permset:perm[,perm,perm...]@namespace/resource [permset...]",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "expiry, e",
					Value:  "30d",
					Usage:  "set the expiry measured from now e.g. 10d5h10s",
					EnvVar: "WAVE_DEFAULT_EXPIRY",
				},
				cli.StringFlag{
					Name:   "attester",
					Usage:  "the granting entity secrets",
					EnvVar: "WAVE_DEFAULT_ENTITY",
				},
				cli.StringFlag{
					Name:  "indirections, indir",
					Usage: "set how many redelegations is permitted",
				},
				cli.StringFlag{
					Name:  "subject",
					Usage: "the recipient entity hash",
				},
				cli.StringFlag{
					Name:  "partition",
					Usage: "the partition that this attestation falls into",
					Value: "",
				},
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "the passphrase to use if required",
				},
				cli.BoolFlag{
					Name:  "nopublish",
					Usage: "do not publish the attestation",
				},
				cli.BoolFlag{
					Name:  "skipsync",
					Usage: "skip graph sync before granting",
				},
				// grant pset:perm,perm,perm@ns/suffix
				oflag,
			},
		},
		{
			Name:   "publish",
			Usage:  "send a wave object to a location",
			Action: cli.ActionFunc(actionPublish),
			Flags: []cli.Flag{
				cli.StringSliceFlag{
					Name:  "location",
					Usage: "a location to publish to",
				},
			},
		},
		{
			Name:      "name",
			Usage:     "name an entity",
			ArgsUsage: "name [options] entity",
			Action:    cli.ActionFunc(actionNameDecl),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "attester",
					Usage:  "the attesting entity secrets",
					EnvVar: "WAVE_DEFAULT_ENTITY",
				},
				cli.StringFlag{
					Name:   "expiry, e",
					Value:  "1000d",
					Usage:  "set the expiry measured from now e.g. 10d5h10s",
					EnvVar: "WAVE_DEFAULT_EXPIRY",
				},
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "the passphrase to use if required",
				},
				cli.BoolFlag{
					Name:  "public",
					Usage: "everyone can see this name",
				},
				cli.StringFlag{
					Name:  "namespace",
					Usage: "(optional) which namespace to place this name declaration in",
				},
				cli.StringFlag{
					Name:  "partition",
					Usage: "(optional) which partition to encrypt this under",
				},
			},
		},
		{
			Name:   "inspect",
			Usage:  "print information about a file",
			Action: cli.ActionFunc(actionInspect),
			Flags:  []cli.Flag{},
		},
		{
			Name:   "verify",
			Usage:  "verify a proof",
			Action: cli.ActionFunc(actionVerify),
		},
		{
			Name:   "resolve",
			Usage:  "print information about a hash/name",
			Action: cli.ActionFunc(actionResolve),
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "perspective",
					Usage:  "the entity to use as a perspective",
					EnvVar: "WAVE_DEFAULT_ENTITY",
				},
				cli.StringFlag{
					Name:  "passphrase",
					Usage: "the passphrase to use if required",
				},
				cli.BoolFlag{
					Name:  "skipsync",
					Usage: "skip graph sync before resolving",
				},
			},
		},
	}

	app.Run(os.Args)
}
