package ds

import dt "github.com/fernandokm/transparencia-de-dominios"

type GetSMHRequest struct {
}

type GetSMHResponse dt.SignedMapHead

type GetDomainRootAndProofRequest struct {
	DomainName    string `schema:"domain_name,required"`
	DomainMapSize uint64 `schema:"domain_map_size,required"`
}

type GetDomainRootAndProofResponse struct {
	DomainTreeSize       uint64   `json:"domain_tree_size"`
	DomainTreeRootHash   []byte   `json:"domain_tree_root_hash"`
	NormalizedDomainName string   `json:"normalized_domain_name"`
	AuditPath            [][]byte `json:"audit_path"`
}

type GetConsistencyProofRequest struct {
	DomainName string `schema:"domain_name,required"`
	First      uint64 `schema:"first,required"`
	Second     uint64 `schema:"second,required"`
}

type GetConsistencyProofResponse struct {
	Proof [][]byte `json:"proof"`
}

type GetEntriesRequest struct {
	DomainName string `schema:"domain_name,required"`
	Start      uint64 `schema:"start,required"`
	End        uint64 `schema:"end,required"`
}

type GetEntriesResponse struct {
	Entries [][2]uint64 `json:"entries"`
}

type GetEntryAndProofRequest struct {
	DomainName     string `schema:"domain_name,required"`
	Index          uint64 `schema:"index,required"`
	DomainTreeSize uint64 `schema:"domain_tree_size,required"`
}

type GetEntryAndProofResponse struct {
	Entry     [2]uint64 `json:"entry"`
	AuditPath [][]byte  `json:"audit_path"`
}

type GetDomainTreeIndexRequest struct {
	DomainName       string `schema:"domain_name,required"`
	LogIndex         uint64 `schema:"log_index,required"`
	CertificateIndex uint64 `schema:"certificate_index,required"`
}

type GetDomainTreeIndexResponse struct {
	DomainTreeIndex uint64 `json:"domain_tree_index"`
}

type GetSourceLogsRequest struct {
	Start uint64 `schema:"start,required"`
	End   uint64 `schema:"end,required"`
}

type GetSourceLogsResponse struct {
	LogIDs [][]byte `json:"log_ids"`
}

type GetSourceLogAndProofRequest struct {
	Index          uint64 `schema:"index,required"`
	SourceTreeSize uint64 `schema:"source_tree_size,required"`
}

type GetSourceLogAndProofResponse struct {
	LogID     []byte   `json:"log_id"`
	AuditPath [][]byte `json:"audit_path"`
}

type GetSourceConsistencyProofRequest struct {
	First  uint64 `schema:"first,required"`
	Second uint64 `schema:"second,required"`
}

type GetSourceConsistencyProofResponse struct {
	Proof [][]byte `json:"proof"`
}
