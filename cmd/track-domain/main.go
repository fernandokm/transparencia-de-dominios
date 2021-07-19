package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fernandokm/transparencia-de-dominios/mapclient"
)

var (
	cmd       = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	mapURI    = cmd.String("map_uri", "http://127.0.0.1:8021/", "")
	mapKeyPEM = cmd.String("map_key", "config/publickey.pem", "the map's public key")
	interval  = cmd.Duration("interval", 2*time.Second, "")
	verbose   = cmd.Bool("verbose", false, "")

	domains []string
)

func init() {
	cmd.Var((*stringSliceFlags)(&domains), "domain", "track the specified domain (repeatable)")

	log.SetFlags(log.Ldate | log.Ltime)
}

func main() {
	cmd.Parse(os.Args[1:])
	if len(domains) == 0 {
		log.Printf("No domains specified.")
		flag.Usage()
		return
	}

	mapPubKey, err := loadPublicKey(*mapKeyPEM)
	if err != nil {
		fmt.Printf("Error loading public key: %v\n", err)
		return
	}

	mc := mapclient.New(*mapURI, http.DefaultClient, mapPubKey)
	tracker := NewDomainTracker(mc, domains)

	// init the tracker
	for {
		if _, err := tracker.FetchSMH(); err != nil {
			log.Printf("Error fetching SMH: %v", err)
			time.Sleep(*interval)
		} else {
			break
		}
	}
	tracker.UpdateDomainTreeRoots(false)
	log.Printf("Domain tracker started...")

	// run the tracker
	for {
		if err := tracker.WaitForSMH(*interval); err != nil {
			log.Printf("Error fetching SMH: %v", err)
			time.Sleep(*interval)
			continue
		}
		if *verbose {
			log.Printf("New SMH: timestamp=%d, size=%d, rootHash=%x, sourceRootHash=%x, sourceLogCount=%d",
				tracker.smh.Timestamp, tracker.smh.MapSize, tracker.smh.MapRootHash, tracker.smh.SourceTreeRootHash, len(tracker.smh.SourceLogRevisions))
		} else {
			log.Printf("New SMH: timestamp=%d, size=%d, rootHash=%x..., sourceRootHash=%x..., sourceLogCount=%d",
				tracker.smh.Timestamp, tracker.smh.MapSize, tracker.smh.MapRootHash[:4], tracker.smh.SourceTreeRootHash[:4], len(tracker.smh.SourceLogRevisions))
		}
		updates := tracker.UpdateDomainTreeRoots(true)
		for _, update := range updates {
			h := sha256.New()
			h.Write(update.Cert.Raw)
			if *verbose {
				log.Printf("New certificate for %s:\n  Issuer: %s\n  Subject: %s\n  SHA-256 Fingerprint: %x\n  Leaf Index: %d",
					strings.Join(update.Domains, ", "), update.Cert.Issuer, update.Cert.Subject, h.Sum(nil), update.LeafIndex)
			} else {
				log.Printf("New certificate for %s:\n  SHA-256 Fingerprint: %x\n  Leaf Index: %d",
					strings.Join(update.Domains, ", "), h.Sum(nil), update.LeafIndex)
			}
		}
	}

}
