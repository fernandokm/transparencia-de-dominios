package ds

import (
	"fmt"
	"net/url"

	dt "github.com/fernandokm/transparencia-de-dominios"
	"github.com/fernandokm/transparencia-de-dominios/util"
	"github.com/gorilla/schema"
)

var decoder = schema.NewDecoder()

// A dtHandler handles requests to a domain transparency server.
type dtHandler struct {
	dm *dt.DomainMap
}

// GET /dt/v1/get-smh
// Params:
//     <none>
// Response:
//     timestamp: integer
//     map_size: integer
//     map_root_hash: base64
//     source_tree_root_hash: base64
//     source_log_revisions: array of {tree_size: integer, root_hash: base64}
//     map_head_signature: base64
func (h *dtHandler) getSMH(query url.Values) (interface{}, error) {
	var req GetSMHRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	return (*GetSMHResponse)(h.dm.GetLatestSMH()), nil
}

// GET /dt/v1/get-consistency-proof
// Params:
//     domain_name: string
//     first: integer
//     second: integer
// Response:
//     proof: array of base64
func (h *dtHandler) getConsistencyProof(query url.Values) (interface{}, error) {
	var req GetConsistencyProofRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	if req.First >= req.Second {
		return nil, fmt.Errorf("invalid sizes: first (%d) >= second (%d)", req.First, req.Second)
	}

	normalizedDomain, err := util.NormalizeDomainName(req.DomainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name %q: %s", req.DomainName, err)
	}

	tree, err := h.dm.GetDomainTree(normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}
	entries := tree.GetConsistencyProof(req.First, req.Second)

	return &GetConsistencyProofResponse{entries}, nil
}

// GET /dt/v1/get-domain-root-and-proof
// Params:
//     domain_name: string
//     domain_map_size: integer
// Response:
//     domain_tree_size: integer
//     domain_tree_root_hash: base64
//     normalized_domain_name: string
//     leaf_hash: base64
//     audit_path: array of base64
func (h *dtHandler) getDomainRootAndProof(query url.Values) (interface{}, error) {
	var req GetDomainRootAndProofRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	normalizedDomain, err := util.NormalizeDomainName(req.DomainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name %q: %s", req.DomainName, err)
	}
	smh := h.dm.GetSMH(req.DomainMapSize)
	if smh == nil {
		return nil, fmt.Errorf("invalid STHTreeSize: %d", req.DomainMapSize)
	}
	root := smh.MapRootHash[:]
	dtr, err := h.dm.GetDomainTreeRoot(root, normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	proof, err := h.dm.GetProofForDomain(root, normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	resp := GetDomainRootAndProofResponse{
		DomainTreeSize:       dtr.DomainTreeSize,
		DomainTreeRootHash:   dtr.DomainTreeRootHash[:],
		NormalizedDomainName: normalizedDomain,
		AuditPath:            proof.Proof,
	}
	return &resp, nil
}

// GET /dt/v1/get-entries
// Params:
//     domain_name: string
//     start: integer
//     end: integer
// Response:
//     entries: array of [integer, integer]
func (h *dtHandler) getEntries(query url.Values) (interface{}, error) {
	var req GetEntriesRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	if req.Start > req.End {
		return nil, fmt.Errorf("invalid range: [%d,%d]", req.Start, req.End)
	}
	normalizedDomain, err := util.NormalizeDomainName(req.DomainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name %q: %s", req.DomainName, err)
	}

	tree, err := h.dm.GetDomainTree(normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}
	entries, err := tree.GetEntries(req.Start, req.End)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	resp := GetEntriesResponse{
		Entries: make([][2]uint64, len(entries)),
	}
	for i, e := range entries {
		resp.Entries[i] = [2]uint64{e.LogIndex, e.CertificateIndex}
	}

	return &resp, nil
}

// GET /dt/v1/get-entry-and-proof
// Params:
//     domain_name: string
//     index: integer
//     domain_tree_size: integer
// Response:
//     entry: [integer, integer]
//     audit_path: array of base64
func (h *dtHandler) getEntryAndProof(query url.Values) (interface{}, error) {
	var req GetEntryAndProofRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	normalizedDomain, err := util.NormalizeDomainName(req.DomainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name %q: %s", req.DomainName, err)
	}

	tree, err := h.dm.GetDomainTree(normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}
	entry, proof, err := tree.GetEntryAndProof(req.DomainTreeSize, req.Index)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	resp := GetEntryAndProofResponse{
		Entry:     [2]uint64{entry.LogIndex, entry.CertificateIndex},
		AuditPath: proof,
	}
	return &resp, nil
}

// GET /dt/v1/get-domain-tree-index
// Params:
//     domain_name: string
//     log_index: integer
//     certificate_index: integer
// Response:
//     domain_tree_index: integer
func (h *dtHandler) getDomainTreeIndex(query url.Values) (interface{}, error) {
	var req GetDomainTreeIndexRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	normalizedDomain, err := util.NormalizeDomainName(req.DomainName)
	if err != nil {
		return nil, fmt.Errorf("invalid domain name %q: %s", req.DomainName, err)
	}

	tree, err := h.dm.GetDomainTree(normalizedDomain)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}
	index, err := tree.EntryToDomainTreeIndex(dt.DomainTreeEntry{
		LogIndex:         req.LogIndex,
		CertificateIndex: req.CertificateIndex,
	})
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	return &GetDomainTreeIndexResponse{index}, nil
}

// GET /dt/v1/get-source-logs
// Params:
//     start: integer
//     end: integer
// Response:
//     log_ids: array of base64
func (h *dtHandler) getSourceLogs(query url.Values) (interface{}, error) {
	var req GetSourceLogsRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	if req.Start > req.End {
		return nil, fmt.Errorf("invalid range: [%d,%d]", req.Start, req.End)
	}
	entries, err := h.dm.GetSourceTree().GetEntries(req.Start, req.End)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	resp := GetSourceLogsResponse{
		LogIDs: make([][]byte, len(entries)),
	}
	for i, e := range entries {
		resp.LogIDs[i] = e.Bytes()
	}

	return &resp, nil
}

// GET /dt/v1/get-source-log-and-proof
// Params:
//     index: integer
//     source_tree_size: integer
// Response:
//     log_id: base64
//     audit_path: array of base64
func (h *dtHandler) getSourceLogAndProof(query url.Values) (interface{}, error) {
	var req GetSourceLogAndProofRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	logID, proof, err := h.dm.GetSourceTree().GetEntryAndProof(req.SourceTreeSize, req.Index)
	if err != nil {
		return nil, fmt.Errorf("error: %s", err)
	}

	resp := GetSourceLogAndProofResponse{
		LogID:     logID.Bytes(),
		AuditPath: proof,
	}
	return &resp, nil
}

// GET /dt/v1/get-source-consistency-proof
// Params:
//     first: integer
//     second: integer
// Response:
//     proof: array of base64
func (h *dtHandler) getSourceConsistencyProof(query url.Values) (interface{}, error) {
	var req GetSourceConsistencyProofRequest
	if err := decoder.Decode(&req, query); err != nil {
		return nil, err
	}
	if req.First >= req.Second {
		return nil, fmt.Errorf("invalid sizes: first (%d) >= second (%d)", req.First, req.Second)
	}

	proof := h.dm.GetSourceTree().GetConsistencyProof(req.First, req.Second)

	return &GetSourceConsistencyProofResponse{proof}, nil
}
