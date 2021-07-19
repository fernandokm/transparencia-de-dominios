package ds

import (
	"context"
	"fmt"
	"time"

	dt "github.com/fernandokm/transparencia-de-dominios"
	"github.com/fernandokm/transparencia-de-dominios/util"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
)

type FetchParams struct {
	InitialTreeSize  uint64
	STHCheckInterval time.Duration
	LogID            [32]byte
	LogIndex         uint64
	LogClient        *client.LogClient
	ReturnOnError    bool

	C chan<- dt.WorkerTransaction
}

// FetchLogForWorker fetches the specified log and passes all entries to the worker.
func FetchLogForWorker(ctx context.Context, params FetchParams) error {
	opts := scanner.DefaultFetcherOptions()
	opts.ParallelFetch = 1
	opts.BatchSize = 64
	opts.StartIndex = int64(params.InitialTreeSize)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		if err := runFetcherIteration(ctx, cancel, params, opts); err != nil {
			if params.ReturnOnError || err == ctx.Err() {
				return err
			} else {
				fmt.Printf("Error (log %d): %v\n", params.LogIndex, err)
				time.Sleep(params.STHCheckInterval)
			}
		}
	}
}

func runFetcherIteration(ctx context.Context, cancel context.CancelFunc, params FetchParams, opts *scanner.FetcherOptions) error {
	opts.EndIndex = 0
	f := scanner.NewFetcher(params.LogClient, opts)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	sth, err := f.Prepare(ctx)
	if err != nil {
		return err
	}
	if opts.EndIndex <= opts.StartIndex {
		time.Sleep(params.STHCheckInterval)
		return nil
	}
	fmt.Printf("Fetcher (log %d): new STH (size=%d)\n", params.LogIndex, sth.TreeSize)
	t := dt.WorkerTransaction{
		LogIndex: params.LogIndex,
		LogID:    params.LogID,
		LogRevision: dt.LogRevision{
			TreeSize: sth.TreeSize,
			RootHash: sth.SHA256RootHash,
		},
		NewCertificatesIndices: make(map[string][]uint64),
	}

	var processErr error

	processFetcherBatch := func(batch scanner.EntryBatch) {
		for i, leaf := range batch.Entries {
			leafIndex := int64(i) + batch.Start
			logEntry, err := ct.LogEntryFromLeaf(leafIndex, &leaf)
			if err != nil && logEntry == nil {
				processErr = err
				cancel()
				return
			}

			var cert *x509.Certificate
			if logEntry.X509Cert != nil {
				cert = logEntry.X509Cert
			} else if logEntry.Precert != nil {
				cert = logEntry.Precert.TBSCertificate
			} else {
				fmt.Printf("Warning (log %d): ignoring JSON Data (index=%d)\n", params.LogIndex, leafIndex)
				continue
			}

			for _, d := range cert.DNSNames {
				d, err := util.NormalizeDomainName(d)
				if err != nil {
					fmt.Printf("Warning (log %d): ignoring invalid domain name for certificate at index=%d: %q\n", params.LogIndex, leafIndex, d)
					continue
				}
				t.NewCertificatesIndices[d] = append(t.NewCertificatesIndices[d], uint64(leafIndex))
			}

			d, err := util.NormalizeDomainName(cert.Subject.CommonName)
			if err != nil {
				if len(cert.DNSNames) == 0 {
					fmt.Printf("Warning (log %d): ignoring certificate at index=%d: no valid domain names found\n", params.LogIndex, leafIndex)
				}
				continue
			}
			t.NewCertificatesIndices[d] = append(t.NewCertificatesIndices[d], uint64(leafIndex))
		}
	}

	if err := f.Run(ctx, processFetcherBatch); err != nil {
		return err
	}
	if processErr != nil {
		return fmt.Errorf("error processing data: %w", processErr)
	}

	params.C <- t
	opts.StartIndex = int64(sth.TreeSize)
	return nil
}
