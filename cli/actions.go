package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/howeyc/gopass"
	"github.com/immesys/wave/consts"
	"github.com/immesys/wave/eapi"
	"github.com/immesys/wave/eapi/pb"
	"github.com/immesys/wave/iapi"
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
	var pass []byte
	if !c.Bool("nopassphrase") {
		fmt.Printf("enter a passphrase for your entity: ")
		pass, err = gopass.GetPasswdMasked()
		if err != nil {
			fmt.Printf("could not read passphrase: %v\n", err)
			os.Exit(1)
		}
	}
	resp, err := conn.CreateEntity(context.Background(), &pb.CreateEntityParams{
		ValidFrom:        time.Now().UnixNano() / 1e6,
		ValidUntil:       time.Now().Add(*expiry).UnixNano() / 1e6,
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
	if !c.Bool("nopublish") {
		presp, err := conn.PublishEntity(context.Background(), &pb.PublishEntityParams{
			DER: resp.PublicDER,
		})
		if err != nil {
			fmt.Printf("publish error: %v\n", err)
			os.Exit(1)
		}
		if presp.Error != nil {
			fmt.Printf("publish error: %s\n", presp.Error.Message)
			os.Exit(1)
		}
	}
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
	conn := getConn(c)
	perspective := getPerspective(c.String("attester"), c.String("passphrase"), "missing attesting entity secret\n")

	if !c.Bool("skipsync") {
		resp, err := conn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
			Perspective: perspective,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		srv, err := conn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
			Perspective: perspective,
		})
		for {
			rv, err := srv.Recv()
			if err == io.EOF {
				break
			}
			fmt.Printf("Synchronized %d/%d entities\n", rv.CompletedSyncs, rv.TotalSyncRequests)
		}
		fmt.Printf("Perspective graph sync complete\n")
	}

	subject := resolveEntityNameOrHashOrFile(conn, perspective, c.String("subject"), "missing subject entity")

	statements := []*pb.RTreePolicyStatement{}

	var namespace []byte
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
		pset := resolveEntityNameOrHashOrFile(conn, perspective, firstsplit[0], "bad permission set")
		perms := strings.SplitN(firstsplit[1], ",", -1)
		nsrez := strings.SplitN(atsplit[1], "/", 2)
		if namespace == nil {
			namespace = resolveEntityNameOrHashOrFile(conn, perspective, nsrez[0], "bad namespace")
		} else {
			namespace2 := resolveEntityNameOrHashOrFile(conn, perspective, nsrez[0], "bad namespace")
			if !bytes.Equal(namespace, namespace2) {
				fmt.Printf("all statements in a single attestation must concern the same namespace\n")
				os.Exit(1)
			}
		}
		statements = append(statements, &pb.RTreePolicyStatement{
			PermissionSet: pset,
			Permissions:   perms,
			Resource:      nsrez[1],
		})
	}
	vizparts := strings.Split(c.String("partition"), "/")
	vizuri := make([][]byte, len(vizparts))
	for idx, s := range vizparts {
		vizuri[idx] = []byte(s)
	}
	pol := &pb.RTreePolicy{
		Namespace:     namespace,
		Indirections:  uint32(c.Int("indirections")),
		Statements:    statements,
		VisibilityURI: vizuri,
	}
	inspectresponse, err := conn.Inspect(context.Background(), &pb.InspectParams{
		Content: perspective.EntitySecret.DER,
	})
	if err != nil {
		fmt.Printf("could not get attester hash: %v\n", err)
		os.Exit(1)
	}
	if inspectresponse.Entity == nil {
		fmt.Printf("attester file is not an entity secret\n")
		os.Exit(1)
	}
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
		Perspective:     perspective,
		BodyScheme:      eapi.BodySchemeWaveRef1,
		SubjectHash:     subject,
		SubjectLocation: subjresp.Location,
		ValidFrom:       time.Now().UnixNano() / 1e6,
		ValidUntil:      time.Now().Add(*expires).UnixNano() / 1e6,
		Policy: &pb.Policy{
			RTreePolicy: pol,
		},
	}
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
	if !c.Bool("nopublish") {
		presp, err := conn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
			DER: resp.DER,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if presp.Error != nil {
			fmt.Printf("error: %s\n", presp.Error.Message)
			os.Exit(1)
		}
		fmt.Printf("published attestation\n")
	}
	return nil
}
func formatPartition(p [][]byte) string {

	if p == nil {
		return "< unknown >"
	}
	realp := make([][]byte, 20)
	for i, e := range p {
		if len(e) != 0 {
			realp[i] = e
		}
	}
	return iapi.WR1PartitionToIntString(realp)
	// if p == nil {
	// 	return "< unknown >"
	// }
	// rv := ""
	// for idx, el := range p {
	// 	if len(el) != 0 {
	// 		rv += fmt.Sprintf("%d:%q ", idx, el)
	// 	}
	// }
	// return strings.TrimSpace(rv)
}
func actionResolve(c *cli.Context) error {
	conn := getConn(c)

	perspective := getPerspective(c.String("perspective"), c.String("passphrase"), "missing perspective parameter\n")
	if !c.Bool("skipsync") {
		resp, err := conn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
			Perspective: perspective,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		srv, err := conn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
			Perspective: perspective,
		})
		for {
			rv, err := srv.Recv()
			if err == io.EOF {
				break
			}
			fmt.Printf("Synchronized %d/%d entities\n", rv.CompletedSyncs, rv.TotalSyncRequests)
		}
		fmt.Printf("Perspective graph sync complete\n")
	}
	for _, a := range c.Args() {
		fmt.Printf("%q:\n", a)
		if len(a) == 48 && strings.Index(a, ".") == -1 {
			//Probably a hash
			h, err := base64.URLEncoding.DecodeString(a)
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
				reverse := ReverseName(conn, perspective, resp.Entity.Hash)
				PrintEntity(resp.Entity, resp.Location, reverse)
			}
			if resp.Attestation != nil {
				PrintAttestation(resp.Attestation, resp.Location, conn, perspective)
			}
		} else {
			//Probably a name
			resp, err := conn.ResolveName(context.Background(), &pb.ResolveNameParams{
				Perspective: perspective,
				Name:        a,
			})
			if err != nil {
				fmt.Printf("could not resolve name: %s\n", err.Error())
				os.Exit(1)
			}
			if resp.Error != nil {
				fmt.Printf("could not resolve name: [%d] %s\n", resp.Error.Code, resp.Error.Message)
				os.Exit(1)
			}
			reverse := ReverseName(conn, perspective, resp.Entity.Hash)
			PrintEntity(resp.Entity, resp.Location, reverse)
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
func actionVerify(c *cli.Context) error {
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
		resp, err := conn.VerifyProof(context.Background(), &pb.VerifyProofParams{
			ProofDER: block.Bytes,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: [%d] %s\n", resp.Error.Code, resp.Error.Message)
			os.Exit(1)
		}
		printProof(resp.Result)
	}
	return nil
}
func printProof(p *pb.Proof) error {
	fmt.Printf("Referenced attestations:\n")
	for idx, att := range p.Elements {
		fmt.Printf(" [%02d] Hash: %s\n", idx, base64.URLEncoding.EncodeToString(att.Hash))
	}
	fmt.Printf("Paths:\n")
	for idx, pe := range p.Paths {
		rv := ""
		for _, el := range pe.Elements {
			rv += fmt.Sprintf("%02d ", el)
		}
		rv = strings.TrimSpace(rv)
		fmt.Printf(" [%02d] %s\n", idx, rv)
	}
	fmt.Printf("Subject: %s\n", base64.URLEncoding.EncodeToString(p.Subject))
	fmt.Printf("SubjectLoc: %s\n", p.SubjectLocation.AgentLocation)
	fmt.Printf("Expires: %s\n", time.Unix(0, p.Expiry*1e6))
	fmt.Printf("Policy: RTree\n")
	fmt.Printf(" Namespace: %s\n", base64.URLEncoding.EncodeToString(p.Policy.RTreePolicy.Namespace))
	fmt.Printf(" Indirections: %d\n", p.Policy.RTreePolicy.Indirections)
	fmt.Printf(" Statements:\n")
	for idx, st := range p.Policy.RTreePolicy.Statements {
		fmt.Printf(" [%02d] Permission set: %s\n", idx, base64.URLEncoding.EncodeToString(st.PermissionSet))
		fmt.Printf("      Permissions: %s\n", strings.Join(st.Permissions, ", "))
		fmt.Printf("      URI: %s\n", st.Resource)
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
					fmt.Printf("error: %s\n", resp.Error.Message)
					os.Exit(1)
				}
			}
		case eapi.PEM_ATTESTATION:
			if len(c.StringSlice("location")) != 0 {
				fmt.Printf("ignoring location parameter for published attestation\n")
			}
			resp, err := conn.PublishAttestation(context.Background(), &pb.PublishAttestationParams{
				DER: block.Bytes,
			})
			if err != nil {
				fmt.Printf("error: %v\n", err)
				os.Exit(1)
			}
			if resp.Error != nil {
				fmt.Printf("error: %s\n", resp.Error.Message)
				os.Exit(1)
			}
		default:
			fmt.Printf("unknown block type %q\n", block.Type)
			os.Exit(1)
		}
	}
	return nil
}
func getPerspective(file string, passphrase string, msg string) *pb.Perspective {
	if file != "" {
		pass := []byte(passphrase)
		if len(pass) == 0 {
			fmt.Printf("passphrase for entity secret: ")
			var err error
			pass, err = gopass.GetPasswdMasked()
			if err != nil {
				fmt.Printf("could not read passphrase: %v\n", err)
				os.Exit(1)
			}
		}
		pder := loadEntitySecretDER(file)
		perspective := &pb.Perspective{
			EntitySecret: &pb.EntitySecret{
				DER:        pder,
				Passphrase: pass,
			},
		}
		return perspective
	} else {
		fmt.Printf(msg)
		os.Exit(1)
		return nil
	}
}
func actionRTProve(c *cli.Context) error {
	conn := getConn(c)
	perspective := getPerspective(c.String("subject"), c.String("passphrase"), "missing subject entity secrets")

	if !c.Bool("skipsync") {
		resp, err := conn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
			Perspective: perspective,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		srv, err := conn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
			Perspective: perspective,
		})
		for {
			rv, err := srv.Recv()
			if err == io.EOF {
				break
			}
			fmt.Printf("Synchronized %d/%d entities\n", rv.CompletedSyncs, rv.TotalSyncRequests)
		}
		fmt.Printf("Perspective graph sync complete\n")
	}

	statements := []*pb.RTreePolicyStatement{}
	var namespace []byte
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
		pset := resolveEntityNameOrHashOrFile(conn, perspective, firstsplit[0], "bad permission set")
		perms := strings.SplitN(firstsplit[1], ",", -1)
		nsrez := strings.SplitN(atsplit[1], "/", 2)
		if namespace == nil {
			namespace = resolveEntityNameOrHashOrFile(conn, perspective, nsrez[0], "bad namespace")
		} else {
			namespace2 := resolveEntityNameOrHashOrFile(conn, perspective, nsrez[0], "bad namespace")
			if !bytes.Equal(namespace, namespace2) {
				fmt.Printf("all statements in a single attestation must concern the same namespace\n")
				os.Exit(1)
			}
		}
		statements = append(statements, &pb.RTreePolicyStatement{
			PermissionSet: pset,
			Permissions:   perms,
			Resource:      nsrez[1],
		})
	}
	inspectresponse, err := conn.Inspect(context.Background(), &pb.InspectParams{
		Content: perspective.EntitySecret.DER,
	})
	if err != nil {
		fmt.Printf("could not get attester hash: %v\n", err)
		os.Exit(1)
	}
	if inspectresponse.Entity == nil {
		fmt.Printf("attester file is not an entity secret\n")
		os.Exit(1)
	}
	//fmt.Printf("inspect hash was: %s\n", base64.URLEncoding.EncodeToString(inspectresponse.Entity.Hash))
	//Get the attester location
	subjectresp, err := conn.ResolveHash(context.Background(), &pb.ResolveHashParams{
		Hash: inspectresponse.Entity.Hash,
	})
	if err != nil {
		fmt.Printf("could not find subject location: %v\n", err)
		os.Exit(1)
	}
	if subjectresp.Error != nil {
		fmt.Printf("could not find subject location: %v\n", subjectresp.Error.Message)
		os.Exit(1)
	}
	perspective.Location = subjectresp.Location
	params := &pb.BuildRTreeParams{
		Perspective:    perspective,
		SubjectHash:    inspectresponse.Entity.Hash,
		RtreeNamespace: namespace,
		Statements:     statements,
	}

	resp, err := conn.BuildRTreeProof(context.Background(), params)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("error: %v\n", resp.Error.Message)
		os.Exit(1)
	}
	bl := pem.Block{
		Type:  eapi.PEM_EXPLICIT_PROOF,
		Bytes: resp.ProofDER,
	}
	outfilename := fmt.Sprintf("proof_%s.pem", time.Now().Format(time.RFC3339))
	if c.String("outfile") != "" {
		outfilename = c.String("outfile")
	}
	err = ioutil.WriteFile(outfilename, pem.EncodeToMemory(&bl), 0600)
	if err != nil {
		fmt.Printf("could not write proof file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote proof: %s\n", outfilename)
	return nil
}

func resolveEntityNameOrHashOrFile(conn pb.WAVEClient, perspective *pb.Perspective, in string, msg string) (hash []byte) {
	f, err := ioutil.ReadFile(in)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error opening file %q: %v\n", in, err)
			os.Exit(1)
		}
		//Resolve as name/hash
		if len(in) == 48 && strings.Index(in, ".") == -1 {
			//Resolve as hash
			rv, err := base64.URLEncoding.DecodeString(in)
			if err != nil {
				fmt.Printf("bad base64: %q\n", in)
				os.Exit(1)
			}
			return rv
		}
		//Resolve as name
		if in == "wave" {
			//Hardcoded builtin PSET
			rv, _ := base64.URLEncoding.DecodeString(consts.WaveBuiltinPSET)
			return rv
		}
		resp, err := conn.ResolveName(context.Background(), &pb.ResolveNameParams{
			Perspective: perspective,
			Name:        in,
		})
		if err != nil {
			fmt.Printf("could not resolve name: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("could not resolve name %q: %s\n", in, resp.Error.Message)
			os.Exit(1)
		}
		return resp.Entity.Hash
	}
	//Resolve as file
	resp, err := conn.Inspect(context.Background(), &pb.InspectParams{
		Content: f,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("could not inspect file: %s\n", resp.Error.Message)
		os.Exit(1)
	}
	if resp.Entity != nil {
		return resp.Entity.Hash
	}
	fmt.Printf(msg)
	os.Exit(1)
	return nil
}
func actionNameDecl(c *cli.Context) error {
	if len(c.Args()) != 2 {
		fmt.Printf("usage: name [flags] entity name\n")
		os.Exit(1)
	}
	expiry, err := ParseDuration(c.String("expiry"))
	if err != nil {
		fmt.Printf("bad expiry: %v\n", err)
		os.Exit(1)
	}
	if expiry == nil {
		panic("no expiry")
	}
	conn := getConn(c)
	persp := getPerspective(c.String("attester"), c.String("passphrase"), "missing attester entity secrets\n")
	entityArg := c.Args()[0]
	isPublic := c.Bool("public")
	nsArg := c.String("namespace")
	partparts := strings.Split(c.String("partition"), "/")
	partition := make([][]byte, len(partparts))
	for idx, s := range partparts {
		partition[idx] = []byte(s)
	}
	subject := resolveEntityNameOrHashOrFile(conn, persp, entityArg, "bad subject argument\n")
	var ns []byte
	if nsArg != "" {
		ns = resolveEntityNameOrHashOrFile(conn, persp, nsArg, "bad namespace argument\n")
	}

	params := pb.CreateNameDeclarationParams{
		Perspective: persp,
		Name:        c.Args()[1],
		Subject:     subject,
		ValidFrom:   time.Now().UnixNano() / 1e6,
		ValidUntil:  time.Now().Add(*expiry).UnixNano() / 1e6,
	}
	if ns != nil {
		if isPublic {
			fmt.Printf("namespace is not required if making a public name declaration\n")
			os.Exit(1)
		}
		params.Namespace = ns
		params.Partition = partition
	} else {
		if !isPublic {
			//We need the attester hash
			resp, err := conn.Inspect(context.Background(), &pb.InspectParams{
				Content: persp.EntitySecret.DER,
			})
			if err != nil {
				fmt.Printf("unable to obtain attester hash: %v\n", err)
				os.Exit(1)
			}
			if resp.Error != nil {
				fmt.Printf("unable to obtain attester hash: %v\n", resp.Error.Message)
				os.Exit(1)
			}
			if resp.Entity == nil {
				fmt.Printf("unable to obtain attester hashv\n")
				os.Exit(1)
			}
			params.Namespace = resp.Entity.Hash
			params.Partition = [][]byte{[]byte("privatenamedeclarations")}
		}
	}
	resp, err := conn.CreateNameDeclaration(context.Background(), &params)
	if err != nil {
		fmt.Printf("unable to create name: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("unable to create name: %v\n", resp.Error.Message)
		os.Exit(1)
	}
	fmt.Printf("name %q -> %q created successfully\n", params.Name, base64.URLEncoding.EncodeToString(subject))
	os.Exit(0)
	return nil
}

func actionResync(c *cli.Context) error {
	perspective := getPerspective(c.String("perspective"), c.String("passphrase"), "missing perspective entity secrets\n")
	conn := getConn(c)
	resp, err := conn.ResyncPerspectiveGraph(context.Background(), &pb.ResyncPerspectiveGraphParams{
		Perspective: perspective,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("error: %v\n", resp.Error.Message)
		os.Exit(1)
	}
	srv, err := conn.WaitForSyncComplete(context.Background(), &pb.SyncParams{
		Perspective: perspective,
	})
	for {
		rv, err := srv.Recv()
		if err == io.EOF {
			break
		}
		fmt.Printf("Synchronized %d/%d entities\n", rv.CompletedSyncs, rv.TotalSyncRequests)
	}
	fmt.Printf("Perspective graph sync complete\n")
	os.Exit(0)
	return nil
}

func getAttestationByHashOrFile(conn pb.WAVEClient, in string, msg string) []byte {
	f, err := ioutil.ReadFile(in)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error opening file %q: %v\n", in, err)
			os.Exit(1)
		}
		//Resolve as name/hash
		if len(in) == 48 && strings.Index(in, ".") == -1 {
			//Resolve as hash
			rv, err := base64.URLEncoding.DecodeString(in)
			if err != nil {
				fmt.Printf("bad base64: %q\n", in)
				os.Exit(1)
			}
			return rv
		}
		fmt.Printf("malformed hash\n")
		os.Exit(1)
	}
	//Resolve as file
	resp, err := conn.Inspect(context.Background(), &pb.InspectParams{
		Content: f,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("could not inspect file: %s\n", resp.Error.Message)
		os.Exit(1)
	}
	if resp.Attestation != nil {
		return resp.Attestation.Hash
	}
	fmt.Printf(msg)
	os.Exit(1)
	return nil
}

func getNameDeclarationByNameHashOrFile(persp *pb.Perspective, conn pb.WAVEClient, in string, msg string) []byte {
	f, err := ioutil.ReadFile(in)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Printf("Error opening file %q: %v\n", in, err)
			os.Exit(1)
		}
		//Resolve as name/hash
		if len(in) == 48 && strings.Index(in, ".") == -1 {
			//Resolve as hash
			rv, err := base64.URLEncoding.DecodeString(in)
			if err != nil {
				fmt.Printf("bad base64: %q\n", in)
				os.Exit(1)
			}
			return rv
		}
		//Resolve as name
		resp, err := conn.ResolveName(context.Background(), &pb.ResolveNameParams{
			Perspective: persp,
			Name:        in,
		})
		if err != nil {
			fmt.Printf("could not resolve name: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("could not resolve name: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		return resp.Derivation[0].Hash
	}
	//Resolve as file
	resp, err := conn.Inspect(context.Background(), &pb.InspectParams{
		Content: f,
	})
	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	if resp.Error != nil {
		fmt.Printf("could not inspect file: %s\n", resp.Error.Message)
		os.Exit(1)
	}
	fmt.Printf("we don't support revoking name declarations by file\n")
	os.Exit(1)
	return nil
}

func actionRevoke(c *cli.Context) error {
	conn := getConn(c)
	if c.String("entity") != "" {
		perspective := getPerspective(c.String("entity"), c.String("passphrase"), "missing perspective entity secrets")
		resp, err := conn.Revoke(context.Background(), &pb.RevokeParams{
			Perspective:       perspective,
			RevokePerspective: true,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		fmt.Printf("entity revoked\n")
		os.Exit(0)
	}
	perspective := getPerspective(c.String("attester"), c.String("passphrase"), "missing attesting entity")
	if c.String("attestation") != "" {
		if c.String("name") != "" {
			fmt.Printf("only one of --attestation and --name is allowed\n")
			os.Exit(1)
		}
		//Get the attestation by hash or file
		atthash := getAttestationByHashOrFile(conn, c.String("attestation"), "bad --attestation\n")
		resp, err := conn.Revoke(context.Background(), &pb.RevokeParams{
			Perspective:     perspective,
			AttestationHash: atthash,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		fmt.Printf("attestation revoked\n")
		os.Exit(0)
	}

	if c.String("name") != "" {
		//Revoke name decl
		hash := getNameDeclarationByNameHashOrFile(perspective, conn, c.String("name"), "bad name")
		resp, err := conn.Revoke(context.Background(), &pb.RevokeParams{
			Perspective:         perspective,
			NameDeclarationHash: hash,
		})
		if err != nil {
			fmt.Printf("error: %v\n", err)
			os.Exit(1)
		}
		if resp.Error != nil {
			fmt.Printf("error: %v\n", resp.Error.Message)
			os.Exit(1)
		}
		fmt.Printf("name declaration revoked\n")
		os.Exit(0)
	}
	return nil
}
