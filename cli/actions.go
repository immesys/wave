package main

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/howeyc/gopass"
	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/urfave/cli"
	"google.golang.org/grpc"
)

//ParseDuration is a little like the existing time.ParseDuration
//but adds days and years because its really annoying not having that
func ParseDuration(s string) (*time.Duration, error) {
	if s == "" {
		return nil, nil
	}
	pat := regexp.MustCompile(`^(\d+y)?(\d+d)?(\d+h)?(\d+m)?(\d+s)?$`)
	res := pat.FindStringSubmatch(s)
	if res == nil {
		return nil, fmt.Errorf("Invalid duration")
	}
	res = res[1:]
	sec := int64(0)
	for idx, mul := range []int64{365 * 24 * 60 * 60, 24 * 60 * 60, 60 * 60, 60, 1} {
		if res[idx] != "" {
			key := res[idx][:len(res[idx])-1]
			v, e := strconv.ParseInt(key, 10, 64)
			if e != nil { //unlikely
				return nil, e
			}
			sec += v * mul
		}
	}
	rv := time.Duration(sec) * time.Second
	return &rv, nil
}

func getConn(c *cli.Context) pb.WAVEClient {
	conn, err := grpc.Dial(c.GlobalString("agent"), grpc.WithInsecure(), grpc.FailOnNonTempDialError(true), grpc.WithBlock())
	if err != nil {
		fmt.Printf("failed to connect to agent: %v\n", err)
		os.Exit(1)
	}
	client := pb.NewWAVEClient(conn)
	return client
}
func actionListLocations(c *cli.Context) error {
	conn := getConn(c)
	locs, err := conn.ListLocations(context.Background(), &pb.ListLocationsParams{})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if locs.Error != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	for name, loc := range locs.AgentLocations {
		if loc.LocationURI == nil {
			fmt.Printf("this tool must be out of date, we don't expect this\n")
			os.Exit(1)
		}
		fmt.Printf("%s : HTTP v%d at %s\n", name, loc.LocationURI.Version, loc.LocationURI.URI)
	}
	return nil
}

func actionMkEntity(c *cli.Context) error {
	conn := getConn(c)
	expiry, err := ParseDuration(c.String("expiry"))
	if err != nil {
		fmt.Printf("bad expiry: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("enter a passphrase for your entity: ")
	pass, err := gopass.GetPasswdMasked()
	if err != nil {
		fmt.Printf("could not read passphrase: %v\n", err)
		os.Exit(1)
	}
	_ = expiry
	resp, err := conn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		//ValidFrom:        time.Now().UnixNano() / 1e6,
		//ValidUntil:       time.Now().Add(*expiry).UnixNano() / 1e6,
		SecretPassphrase: string(pass),
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("error: [%d] %v\n", resp.Error.Code, resp.Error.Message)
		os.Exit(1)
	}
	bl := pem.Block{
		Type:  eapi.PEM_ENTITY_SECRET,
		Bytes: resp.SecretDER,
	}
	stringhash := base64.URLEncoding.EncodeToString(resp.Hash)
	filename := "ent_" + stringhash + ".pem"
	if c.String("outfile") != "" {
		filename = c.String("outfile")
	}
	err = ioutil.WriteFile(filename, pem.EncodeToMemory(&bl), 0600)
	if err != nil {
		fmt.Printf("could not write entity file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote entity: %s\n", filename)
	return nil
}
func loadEntitySecretDER(filename string) []byte {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		fmt.Printf("could not read file %q: %v\n", filename, err)
		os.Exit(1)
	}
	block, _ := pem.Decode(contents)
	if block == nil {
		fmt.Printf("file %q is not a PEM file\n", filename)
		os.Exit(1)
	}
	if block.Type != eapi.PEM_ENTITY_SECRET {
		fmt.Printf("PEM is not an entity secret\n")
		os.Exit(1)
	}
	return block.Bytes
}
func actionRTGrant(c *cli.Context) error {
	expires, err := ParseDuration(c.String("expiry"))
	if err != nil {
		fmt.Printf("bad expiry\n")
		os.Exit(1)
	}
	fmt.Printf("expires is %s\n", expires)
	attesterder := loadEntitySecretDER(c.String("attester"))
	subject, err := base64.URLEncoding.DecodeString(c.String("subject"))
	if err != nil {
		fmt.Printf("bad subject hash\n")
		os.Exit(1)
	}
	//TODO passphrase from cli args
	fmt.Printf("enter the passphrase for the attesting entity: ")
	pass, err := gopass.GetPasswdMasked()
	if err != nil {
		fmt.Printf("could not read passphrase: %v\n", err)
		os.Exit(1)
	}
	statements := []*pb.RTreePolicyStatement{}
	var namespace string
	if len(c.Args()) == 0 {
		fmt.Printf("need to specify some statements\n")
		os.Exit(1)
	}
	for _, a := range c.Args() {
		atsplit := strings.SplitN(a, "@", -1)
		if len(atsplit) != 2 {
			fmt.Printf("%v\n", atsplit)
			fmt.Printf("err 1 expected arguments of form permset:perm[,perm,perm...]@namespace/resource\n")
			os.Exit(1)
		}
		firstsplit := strings.SplitN(atsplit[0], ":", -1)
		if len(firstsplit) != 2 {
			fmt.Printf("err 2 expected arguments of form permset:perm[,perm,perm...]@namespace/resource\n")
			os.Exit(1)
		}
		pset, err := base64.URLEncoding.DecodeString(firstsplit[0])
		if err != nil {
			fmt.Printf("permission set invalid\n")
			os.Exit(1)
		}
		perms := strings.SplitN(firstsplit[1], ",", -1)
		nsrez := strings.SplitN(atsplit[1], "/", 2)
		if namespace == "" {
			namespace = nsrez[0]
		}
		if namespace != nsrez[0] {
			fmt.Printf("all statements in a single attestation must be on the same namespace\n")
			os.Exit(1)
		}
		statements = append(statements, &pb.RTreePolicyStatement{
			PermissionSet: pset,
			Permissions:   perms,
			Resource:      nsrez[1],
		})
	}
	ns, err := base64.URLEncoding.DecodeString(namespace)
	if err != nil {
		fmt.Printf("invalid namespace\n")
		os.Exit(1)
	}
	vizparts := strings.Split(c.String("partition"), "/")
	vizuri := make([][]byte, len(vizparts))
	for idx, s := range vizparts {
		vizuri[idx] = []byte(s)
	}
	conn := getConn(c)
	pol := &pb.RTreePolicy{
		Namespace:     ns,
		Indirections:  uint32(c.Int("indirections")),
		Statements:    statements,
		VisibilityURI: vizuri,
	}
	inspectresponse, err := conn.Inspect(context.Background(), &pb.InspectParams{
		Content: attesterder,
	})
	if err != nil {
		fmt.Printf("could not get attester hash: %v\n", err)
		os.Exit(1)
	}
	if inspectresponse.Entity == nil {
		fmt.Printf("attester file is not an entity secret\n")
		os.Exit(1)
	}
	fmt.Printf("inspect hash was: %s\n", base64.URLEncoding.EncodeToString(inspectresponse.Entity.Hash))
	//Get the attester location
	attesterresp, err := conn.ResolveHash(context.Background(), &pb.ResolveHashParams{
		Hash: inspectresponse.Entity.Hash,
	})
	if err != nil {
		fmt.Printf("could not find attester location: %v\n", err)
		os.Exit(1)
	}
	if attesterresp.Error != nil {
		fmt.Printf("could not find attester location: %v\n", attesterresp.Error.Message)
		os.Exit(1)
	}

	subjresp, err := conn.ResolveHash(context.Background(), &pb.ResolveHashParams{
		Hash: subject,
	})
	if err != nil {
		fmt.Printf("could not find subject location: %v\n", err)
		os.Exit(1)
	}
	if subjresp.Error != nil {
		fmt.Printf("could not find subject location: %v\n", subjresp.Error.Message)
		os.Exit(1)
	}
	params := &pb.CreateAttestationParams{
		Perspective: &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        attesterder,
				Passphrase: pass,
			},
			Location: attesterresp.Location,
		},
		BodyScheme:      eapi.BodySchemeWaveRef1,
		SubjectHash:     subject,
		SubjectLocation: subjresp.Location,
		ValidFrom:       time.Now().UnixNano() / 1e6,
		ValidUntil:      time.Now().Add(*expires).UnixNano() / 1e6,
		Policy: &pb.Policy{
			RTreePolicy: pol,
		},
	}
	spew.Dump(pol)
	fmt.Printf("ns %x\n", pol.Namespace)
	resp, err := conn.CreateAttestation(context.Background(), params)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("error: %v\n", resp.Error.Message)
		os.Exit(1)
	}
	bl := pem.Block{
		Type:  eapi.PEM_ATTESTATION,
		Bytes: resp.DER,
	}
	stringhash := base64.URLEncoding.EncodeToString(resp.Hash)
	outfilename := fmt.Sprintf("att_%s.pem", stringhash)
	if c.String("outfile") != "" {
		outfilename = c.String("outfile")
	}
	err = ioutil.WriteFile(outfilename, pem.EncodeToMemory(&bl), 0600)
	if err != nil {
		fmt.Printf("could not write attestation file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote attestation: %s\n", outfilename)
	return nil
}
func formatPartition(p [][]byte) string {
	if p == nil {
		return "< unknown >"
	}
	rv := ""
	for idx, el := range p {
		if len(el) != 0 {
			rv += fmt.Sprintf("%d:%q ", idx, el)
		}
	}
	return strings.TrimSpace(rv)
}
func actionResolve(c *cli.Context) error {
	conn := getConn(c)
	pfile := c.String("perspective")
	var perspective *pb.Perspective
	if pfile != "" {
		pass := []byte(c.String("passphrase"))
		if len(pass) == 0 {
			fmt.Printf("passphrase for perspective entity: ")
			var err error
			pass, err = gopass.GetPasswdMasked()
			if err != nil {
				fmt.Printf("could not read passphrase: %v\n", err)
				os.Exit(1)
			}
		}
		pder := loadEntitySecretDER(pfile)
		perspective = &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        pder,
				Passphrase: pass,
			},
		}
	}

	for _, hash := range c.Args() {
		h, err := base64.URLEncoding.DecodeString(hash)
		if err != nil {
			fmt.Printf("invalid hash\n")
			os.Exit(1)
		}
		resp, err := conn.ResolveHash(context.Background(), &pb.ResolveHashParams{
			Perspective: perspective,
			Hash:        h,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %s\n", resp.Error.Message)
			os.Exit(1)
		}
		if resp.Entity != nil {
			fmt.Printf("= Entity\n")
			fmt.Printf("  Location: %s\n", resp.Location.AgentLocation)
			fmt.Printf("      Hash: %s\n", base64.URLEncoding.EncodeToString(resp.Entity.Hash))
			fmt.Printf("   Created: %s\n", time.Unix(0, resp.Entity.ValidFrom*1e6))
			fmt.Printf("   Expires: %s\n", time.Unix(0, resp.Entity.ValidUntil*1e6))
			fmt.Printf("  Validity:\n")
			fmt.Printf("   - Valid: %v\n", resp.Entity.Validity.Valid)
			fmt.Printf("   - Expired: %v\n", resp.Entity.Validity.Expired)
			fmt.Printf("   - Malformed: %v\n", resp.Entity.Validity.Malformed)
			fmt.Printf("   - Revoked: %v\n", resp.Entity.Validity.Revoked)
			fmt.Printf("   - Message: %v\n", resp.Entity.Validity.Message)
		}
		if resp.Attestation != nil {
			fmt.Printf("= Attestation\n")
			fmt.Printf("  Location: %s\n", resp.Location.AgentLocation)
			fmt.Printf("  Hash : %s\n", base64.URLEncoding.EncodeToString(resp.Attestation.Hash))
			fmt.Printf("  Partition: %s\n", formatPartition(resp.Attestation.Partition))
			if resp.Attestation.Body != nil {
				fmt.Printf("Created: %s\n", time.Unix(0, resp.Attestation.Body.ValidFrom*1e6))
				fmt.Printf("Expires: %s\n", time.Unix(0, resp.Attestation.Body.ValidUntil*1e6))
			}
			fmt.Printf("  Validity:\n")
			fmt.Printf("   - Readable: %v\n", !resp.Attestation.Validity.NotDecrypted)
			fmt.Printf("   - Revoked: %v\n", resp.Attestation.Validity.Revoked)
			fmt.Printf("   - Malformed: %v\n", resp.Attestation.Validity.Malformed)
			fmt.Printf("   - Subject invalid: %v\n", resp.Attestation.Validity.DstInvalid)
			if !resp.Attestation.Validity.NotDecrypted {
				fmt.Printf("   - Valid: %v\n", resp.Attestation.Validity.Valid)
				fmt.Printf("   - Expired: %v\n", resp.Attestation.Validity.Expired)
				fmt.Printf("   - Attester invalid: %v\n", resp.Attestation.Validity.SrcInvalid)
				fmt.Printf("  Policy: RTree\n")
				fmt.Printf("   - Namespace: %s\n", base64.URLEncoding.EncodeToString(resp.Attestation.Body.Policy.RTreePolicy.Namespace))
				fmt.Printf("   - Indirections: %d\n", resp.Attestation.Body.Policy.RTreePolicy.Indirections)
				fmt.Printf("   - Statements:\n")
				for idx, st := range resp.Attestation.Body.Policy.RTreePolicy.Statements {
					fmt.Printf("     [%02d] Permission set: %s\n", idx, base64.URLEncoding.EncodeToString(st.PermissionSet))
					fmt.Printf("          Permissions: %s\n", strings.Join(st.Permissions, ", "))
					fmt.Printf("          URI: %s\n", st.Resource)
				}
			}
		}
	}
	return nil
}
func actionInspect(c *cli.Context) error {
	conn := getConn(c)
	for _, filename := range c.Args() {
		contents, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Printf("could not read file %q: %v\n", filename, err)
			continue
		}
		block, _ := pem.Decode(contents)
		if block == nil {
			fmt.Printf("file %q is not a PEM file\n", filename)
			continue
		}
		resp, err := conn.Inspect(context.Background(), &pb.InspectParams{
			Content: block.Bytes,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: [%d] %s\n", resp.Error.Code, resp.Error.Message)
			os.Exit(1)
		}
		if resp.Entity != nil {
			fmt.Printf("= Entity\n")
			fmt.Printf("      Hash: %s\n", base64.URLEncoding.EncodeToString(resp.Entity.Hash))
			fmt.Printf("   Created: %s\n", time.Unix(0, resp.Entity.ValidFrom*1e6))
			fmt.Printf("   Expires: %s\n", time.Unix(0, resp.Entity.ValidUntil*1e6))
			fmt.Printf("  Validity:\n")
			fmt.Printf("   - Valid: %v\n", resp.Entity.Validity.Valid)
			fmt.Printf("   - Expired: %v\n", resp.Entity.Validity.Expired)
			fmt.Printf("   - Malformed: %v\n", resp.Entity.Validity.Malformed)
			fmt.Printf("   - Revoked: %v\n", resp.Entity.Validity.Revoked)
			fmt.Printf("   - Message: %v\n", resp.Entity.Validity.Message)
		}
		if resp.Attestation != nil {
			fmt.Printf("= Attestation %q\n", filename)
			fmt.Printf("  Hash : %s\n", base64.URLEncoding.EncodeToString(resp.Attestation.Hash))
			if resp.Attestation.Body != nil {
				fmt.Printf("Created: %s\n", time.Unix(0, resp.Attestation.Body.ValidFrom*1e6))
				fmt.Printf("Expires: %s\n", time.Unix(0, resp.Attestation.Body.ValidUntil*1e6))
			}
			fmt.Printf("  Validity:\n")
			fmt.Printf("   - Readable: %v\n", !resp.Attestation.Validity.NotDecrypted)
			fmt.Printf("   - Revoked: %v\n", resp.Attestation.Validity.Revoked)
			fmt.Printf("   - Malformed: %v\n", resp.Attestation.Validity.Malformed)
			fmt.Printf("   - Subject invalid: %v\n", resp.Attestation.Validity.DstInvalid)
			if !resp.Attestation.Validity.NotDecrypted {
				fmt.Printf("   - Valid: %v\n", resp.Attestation.Validity.Valid)
				fmt.Printf("   - Expired: %v\n", resp.Attestation.Validity.Expired)
				fmt.Printf("   - Attester invalid: %v\n", resp.Attestation.Validity.SrcInvalid)
			}
		}
	}
	return nil
}
func actionPublish(c *cli.Context) error {
	conn := getConn(c)
	for _, filename := range c.Args() {
		contents, err := ioutil.ReadFile(filename)
		if err != nil {
			fmt.Printf("could not read file %q: %v\n", filename, err)
			os.Exit(1)
		}
		block, _ := pem.Decode(contents)
		if block == nil {
			fmt.Printf("file %q is not a PEM file\n", filename)
			os.Exit(1)
		}
		switch block.Type {
		case eapi.PEM_ENTITY_SECRET:
			locs := []string{"default"}
			if len(c.StringSlice("location")) != 0 {
				locs = c.StringSlice("location")
			}
			for _, loc := range locs {
				resp, err := conn.PublishEntity(context.Background(), &pb.PublishEntityParams{
					DER: block.Bytes,
					Location: &pb.Location{
						AgentLocation: loc,
					},
				})
				if err != nil {
					fmt.Printf("error: %v\n", err)
					os.Exit(1)
				}
				if resp.Error != nil {
					fmt.Printf("error: [%d] %s\n", resp.Error.Code, resp.Error.Message)
					os.Exit(1)
				}
			}
		case eapi.PEM_ATTESTATION:
			locs := []string{"default"}
			if len(c.StringSlice("location")) != 0 {
				locs = c.StringSlice("location")
			}
			for _, loc := range locs {
				resp, err := conn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
					DER: block.Bytes,
					Location: &pb.Location{
						AgentLocation: loc,
					},
				})
				if err != nil {
					fmt.Printf("error: %v\n", err)
					os.Exit(1)
				}
				if resp.Error != nil {
					fmt.Printf("error: [%d] %s\n", resp.Error.Code, resp.Error.Message)
					os.Exit(1)
				}
			}
		default:
			fmt.Printf("unknown block type %q\n", block.Type)
			os.Exit(1)
		}
	}
	return nil
}
