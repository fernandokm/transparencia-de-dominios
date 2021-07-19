package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/fernandokm/transparencia-de-dominios/mapclient"
	ds "github.com/fernandokm/transparencia-de-dominios/server"
	"github.com/fernandokm/transparencia-de-dominios/util"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/trillian/merkle"
	"github.com/google/trillian/merkle/rfc6962"
)

type Update struct {
	Cert      *x509.Certificate
	Domains   []string
	LogIndex  uint64
	LeafIndex uint64
}

type DomainTracker struct {
	mc      *mapclient.MapClient
	domains []string

	lastTreeSizes map[string]uint64
	smh           *ds.GetSMHResponse
	logClients    []*client.LogClient
	verifier      merkle.LogVerifier
}

func NewDomainTracker(mc *mapclient.MapClient, domains []string) *DomainTracker {
	return &DomainTracker{
		mc:      mc,
		domains: domains,

		lastTreeSizes: make(map[string]uint64),
		smh:           nil,
		logClients:    nil,
		verifier:      merkle.NewLogVerifier(rfc6962.DefaultHasher),
	}
}

func (t *DomainTracker) FetchSMH() (updated bool, err error) {
	smh, err := t.mc.GetAndVerifySMH()
	if err != nil {
		return false, err
	}
	if t.smh != nil && bytes.Equal(t.smh.MapHeadSignature, smh.MapHeadSignature) {
		return false, nil
	}
	t.smh = smh
	return true, nil
}

func (t *DomainTracker) WaitForSMH(fetchInterval time.Duration) error {
	for {
		updated, err := t.FetchSMH()
		if err != nil {
			return err
		} else if updated {
			return nil
		}
		time.Sleep(fetchInterval)
	}
}

func (t *DomainTracker) GetClient(logIndex uint64) (*client.LogClient, error) {
	for uint64(len(t.logClients)) <= logIndex {
		t.logClients = append(t.logClients, nil)
	}
	if t.logClients[logIndex] != nil {
		return t.logClients[logIndex], nil
	}
	resp, err := t.mc.GetSourceLogAndProof(&ds.GetSourceLogAndProofRequest{
		Index:          logIndex,
		SourceTreeSize: uint64(len(t.smh.SourceLogRevisions)),
	})
	if err != nil {
		return nil, err
	}
	var id [32]byte
	copy(id[:], resp.LogID)
	log := util.GetLogList().FindLogByKeyHash(id)
	if log == nil {
		return nil, fmt.Errorf("unknown log with key %x", id)
	}
	return client.New(log.URL, http.DefaultClient, jsonclient.Options{PublicKeyDER: log.Key})
}

func (t *DomainTracker) UpdateDomainTreeRoots(returnUpdates bool) []*Update {
	updatesMap := make(map[[2]uint64]*Update)
	for _, d := range t.domains {
		domainRoot, err := t.mc.GetDomainRootAndProof(&ds.GetDomainRootAndProofRequest{
			DomainName:    d,
			DomainMapSize: t.smh.MapSize,
		})
		if err != nil {
			log.Printf("Error getting domain tree root for %q: %v", d, err)
			continue
		}
		if returnUpdates {
			err := t.getTreeUpdates(domainRoot, t.lastTreeSizes[d], domainRoot.DomainTreeSize, updatesMap)
			if err != nil {
				log.Printf("Error updating tree for %q: %v", d, err)
				continue
			}
		} else {
			t.lastTreeSizes[d] = domainRoot.DomainTreeSize
		}
	}
	updates := make([]*Update, 0, len(updatesMap))
	for _, up := range updatesMap {
		updates = append(updates, up)
	}
	return updates
}

func (t *DomainTracker) getTreeUpdates(domainRoot *ds.GetDomainRootAndProofResponse, from, to uint64, updatesMap map[[2]uint64]*Update) error {
	for i := from; i < to; i++ {
		if err := t.getTreeUpdate(domainRoot, i, updatesMap); err != nil {
			return err
		}
		t.lastTreeSizes[domainRoot.NormalizedDomainName] = i + 1
	}
	return nil
}

func (t *DomainTracker) getTreeUpdate(domainRoot *ds.GetDomainRootAndProofResponse, index uint64, updatesMap map[[2]uint64]*Update) error {
	entryAndProof, err := t.mc.GetEntryAndProof(&ds.GetEntryAndProofRequest{
		DomainName:     domainRoot.NormalizedDomainName,
		DomainTreeSize: domainRoot.DomainTreeSize,
		Index:          index,
	})
	if err != nil {
		return err
	}
	update, ok := updatesMap[entryAndProof.Entry]
	if ok {
		update.Domains = append(update.Domains, domainRoot.NormalizedDomainName)
		return nil
	}
	update = &Update{
		Domains:   []string{domainRoot.NormalizedDomainName},
		LogIndex:  entryAndProof.Entry[0],
		LeafIndex: entryAndProof.Entry[1],
	}
	client, err := t.GetClient(update.LogIndex)
	if err != nil {
		return err
	}
	resp, err := client.GetEntryAndProof(context.Background(), update.LeafIndex, t.smh.SourceLogRevisions[update.LogIndex].TreeSize)
	if err != nil {
		log.Panic(err)
	}
	var leaf ct.MerkleTreeLeaf
	_, err = tls.Unmarshal(resp.LeafInput, &leaf)
	if err != nil {
		return fmt.Errorf("error unmarshalling log entry: %w", err)
	}
	logLeafHash, err := ct.LeafHashForLeaf(&leaf)
	if err != nil {
		return fmt.Errorf("error calculating leaf hash: %w", err)
	}
	err = t.verifier.VerifyInclusionProof(int64(update.LeafIndex), int64(t.smh.SourceLogRevisions[update.LogIndex].TreeSize), resp.AuditPath, t.smh.SourceLogRevisions[update.LogIndex].RootHash[:], logLeafHash[:])
	if err != nil {
		return fmt.Errorf("error verifying CT audit proof: %w", err)
	}
	if leaf.TimestampedEntry.EntryType == ct.X509LogEntryType {
		update.Cert, err = leaf.X509Certificate()
	} else if leaf.TimestampedEntry.EntryType == ct.PrecertLogEntryType {
		update.Cert, err = leaf.Precertificate()
	} else {
		log.Printf("Entry (%d,%d) has json type, skipping", update.LogIndex, update.LeafIndex)
		return nil
	}
	if err != nil {
		return fmt.Errorf("error parsing certificate: %w", err)
	}
	updatesMap[entryAndProof.Entry] = update
	return nil
}
