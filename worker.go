package dt

import (
	"context"
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"github.com/fernandokm/transparencia-de-dominios/util"
	"github.com/google/certificate-transparency-go/logid"
)

// A WorkerTransaction specified the actions to be taken by the worker.
type WorkerTransaction struct {
	LogIndex               uint64
	LogID                  logid.LogID
	LogRevision            LogRevision
	NewCertificatesIndices map[string][]uint64
}

type WorkerConfig struct {
	BufferSize   int
	UpdatePeriod time.Duration
	MMD          time.Duration // This value should be slightly less than the actual MMD
}

type worker struct {
	dm              *DomainMap
	mapSize         uint64
	sourceRevisions []LogRevision
	mapRoot         []byte
	config          WorkerConfig
	queue           []WorkerTransaction
}

func newWorker(dm *DomainMap, config WorkerConfig) *worker {
	smh := dm.GetLatestSMH()
	return &worker{
		dm:              dm,
		mapSize:         smh.MapSize,
		sourceRevisions: smh.SourceLogRevisions[:],
		mapRoot:         smh.MapRootHash[:],
		config:          config,
		queue:           nil,
	}
}

// StartWorker starts a new worker for this domain tree.
// There may only be one running worker per domain tree
// at any time and there should be no manual modifications
// while a worker is running.
// To ensure that a worker has exited after cancelling
// the context, wait for the <-chan struct{} to be closed.
func StartWorker(ctx context.Context, dm *DomainMap, config WorkerConfig) (chan<- WorkerTransaction, <-chan struct{}) {
	c := make(chan WorkerTransaction, config.BufferSize)
	stopped := make(chan struct{})

	go func() {
		w := newWorker(dm, config)
		if err := w.run(ctx, c); err != nil {
			fmt.Printf("Stopped worker: %v\n", err)
		}
		close(stopped)
	}()
	return c, stopped
}

func (w *worker) run(ctx context.Context, c <-chan WorkerTransaction) error {
	updateTicker := time.NewTicker(w.config.UpdatePeriod)
	defer updateTicker.Stop()
	mmdTicker := time.NewTicker(w.config.MMD)
	defer mmdTicker.Stop()

	for {
		notePublishSMH := ""
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-updateTicker.C:
			if w.dm.GetLatestSMH().MapSize != w.mapSize {
				mmdTicker.Reset(w.config.MMD)
				goto publishSHM
			}
		case <-mmdTicker.C:
			if w.dm.GetLatestSMH().MapSize == w.mapSize {
				notePublishSMH = " (republished)"
			}
			goto publishSHM
		case t := <-c:
			if err := w.addToQueueAndProcess(t); err != nil {
				return err
			}
		}
		continue
	publishSHM:
		if w.mapSize == 0 {
			fmt.Printf("Warning: the MMD expired, but the first STH hasn't been fetched yet. Resetting MMD timer.\n")
			continue
		}
		err := w.dm.CheckAndPublishSMH(w.mapRoot, w.mapSize, w.sourceRevisions)
		if err != nil {
			return fmt.Errorf("error publishing new SMH: %w", err)
		}
		smh := w.dm.GetLatestSMH()
		fmt.Printf("New SMH: hash=%s, signature=%s, size=%d, timestamp=%d%s\n",
			base64.StdEncoding.EncodeToString(smh.MapRootHash[:])[:12],
			base64.StdEncoding.EncodeToString(smh.MapHeadSignature[:])[:12],
			smh.MapSize,
			smh.Timestamp,
			notePublishSMH)
	}
}

func (w *worker) addToQueueAndProcess(t WorkerTransaction) error {
	tryProcess := func(t WorkerTransaction) (bool, error) {
		if uint64(len(w.sourceRevisions)) < t.LogIndex {
			// This condition means that the log at index t.LogIndex-1 hasn't been added yet,
			// so the log at t.LogIndex cannot yet be added.
			return false, nil
		}
		return true, w.processTransaction(t)
	}
	if processed, err := tryProcess(t); err != nil {
		return err
	} else if !processed {
		fmt.Printf("Warning: got new certificates from log %d, but log %d can only be added to the source tree once all previous logs have already been added\n", t.LogIndex, t.LogIndex)
		w.queue = append(w.queue, t)
	}

	for i := 0; i < len(w.queue); i++ {
		tt := w.queue[i]
		if processed, err := tryProcess(tt); err != nil {
			return err
		} else if processed {
			w.queue = append(w.queue[:i], w.queue[i+1:]...)
			i -= 1
		}
	}
	return nil
}

func (w *worker) processTransaction(t WorkerTransaction) error {
	if uint64(len(w.sourceRevisions)) == t.LogIndex {
		fmt.Printf("Adding log %d to the source tree\n", t.LogIndex)
		w.sourceRevisions = append(w.sourceRevisions, LogRevision{})
		w.dm.GetSourceTree().AddEntry(t.LogID)
	} else if uint64(len(w.sourceRevisions)) < t.LogIndex {
		return fmt.Errorf("attempt to add certificates from log %d when log %d hasn't been added yet", t.LogIndex, len(w.sourceRevisions))
	}
	oldRev := w.sourceRevisions[t.LogIndex]
	newRev := t.LogRevision

	w.mapSize += newRev.TreeSize - oldRev.TreeSize
	w.sourceRevisions[t.LogIndex] = newRev

	for domain, certIndices := range t.NewCertificatesIndices {
		if len(certIndices) == 0 {
			continue
		}
		dtree, err := w.getDomainTree(domain)
		if err != nil {
			return err
		}
		sort.Slice(certIndices, func(i, j int) bool { return certIndices[i] < certIndices[j] })
		var treeSize uint64
		for _, certIndex := range certIndices {
			treeSize = dtree.AddEntry(DomainTreeEntry{
				LogIndex:         t.LogIndex,
				CertificateIndex: certIndex,
			})
		}
		w.mapRoot, err = w.dm.UpdateDomainTreeRoot(w.mapRoot, dtree.DomainName, treeSize)
		if err != nil {
			return fmt.Errorf("error propagating tree root update for %q to the domain tree: %w", dtree.DomainName, err)
		}
	}
	return nil
}

func (w *worker) getDomainTree(domain string) (*DomainTree, error) {
	normalizedDomain, err := util.NormalizeDomainName(domain)
	if err != nil {
		return nil, fmt.Errorf("error normalizing domain name %q: %w", domain, err)
	}
	dtree, err := w.dm.GetDomainTree(normalizedDomain)
	if err == nil {
		return dtree, nil
	}

	dtree, err = NewDomainTree(normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error creating domain tree for %q: %w", normalizedDomain, err)
	}
	if err := w.dm.AddDomainTree(dtree); err != nil {
		return nil, fmt.Errorf("error adding new domain tree do the domain map: %w", err)
	}
	return dtree, nil
}
