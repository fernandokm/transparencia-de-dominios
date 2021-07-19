package ds

import (
	"fmt"
	"net/http"
	"time"

	dt "github.com/fernandokm/transparencia-de-dominios"
)

// NewServer creates a new domain server.
// The handler flags should only be modified BEFORE calling serve().
func NewServer(dm *dt.DomainMap, ip string, port int) (*http.Server, *dtHandler) {
	h := &dtHandler{dm}
	mux := http.NewServeMux()
	mux.Handle("/dt/v1/get-smh", dtHandlerFunc(h.getSMH))
	mux.Handle("/dt/v1/get-domain-root-and-proof", dtHandlerFunc(h.getDomainRootAndProof))
	mux.Handle("/dt/v1/get-consistency-proof", dtHandlerFunc(h.getConsistencyProof))
	mux.Handle("/dt/v1/get-entries", dtHandlerFunc(h.getEntries))
	mux.Handle("/dt/v1/get-entry-and-proof", dtHandlerFunc(h.getEntryAndProof))
	mux.Handle("/dt/v1/get-domain-tree-index", dtHandlerFunc(h.getDomainTreeIndex))
	mux.Handle("/dt/v1/get-source-logs", dtHandlerFunc(h.getSourceLogs))
	mux.Handle("/dt/v1/get-source-log-and-proof", dtHandlerFunc(h.getSourceLogAndProof))
	mux.Handle("/dt/v1/get-source-consistency-proof", dtHandlerFunc(h.getSourceConsistencyProof))
	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", ip, port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}, h
}
