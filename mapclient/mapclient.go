package mapclient

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	ds "github.com/fernandokm/transparencia-de-dominios/server"
	"github.com/fernandokm/transparencia-de-dominios/util"
	"github.com/google/certificate-transparency-go/tls"
	"github.com/gorilla/schema"
)

var encoder = schema.NewEncoder()

// A MapClient represents a client for a domain map.
type MapClient struct {
	uri       string
	client    *http.Client
	publicKey *ecdsa.PublicKey
}

// New creates a new MapClient.
func New(uri string, client *http.Client, publicKey *ecdsa.PublicKey) *MapClient {
	uri = strings.TrimRight(uri, "/") + "/"
	return &MapClient{uri, client, publicKey}
}

// URI returns the uri of this map. This uri always has a trailing slash.
func (mc *MapClient) URI() string {
	return mc.uri
}

// get encodes `params` using schema, executes the `command`, and returns the JSON-decoded `output`.
func (mc *MapClient) get(command string, output interface{}, params interface{}) error {
	path := mc.uri + command
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		return err
	}

	q := req.URL.Query()
	if err := encoder.Encode(params, q); err != nil {
		return err
	}
	req.URL.RawQuery = q.Encode()

	res, err := mc.client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			fmt.Printf("Error closing request body: %v\n", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("got http response " + res.Status)
	}

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, output)
}

// verifySignatureTLS verifies a signature after TLS-encoding the data
func (mc *MapClient) verifySignatureTLS(data interface{}, signature []byte) error {
	bytes, err := tls.Marshal(data)
	if err != nil {
		return fmt.Errorf("signature verification error: couldn't TLS-encode the MapHead: %w", err)
	}

	if !ecdsa.VerifyASN1(mc.publicKey, util.HashBytes(bytes), signature) {
		return fmt.Errorf("couldn't verify signature")
	}
	return nil
}

// GetAndVerifySMH executes `GET /dt/v1/get-smh`
// and verifies the SMH signature, if a public key is available.
func (mc *MapClient) GetAndVerifySMH() (*ds.GetSMHResponse, error) {
	var resp ds.GetSMHResponse
	err := mc.get("dt/v1/get-smh", &resp, &ds.GetSMHRequest{})
	if err != nil {
		return nil, err
	}
	resp.Version = 1
	if err := mc.verifySignatureTLS(resp.MapHead, resp.MapHeadSignature); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDomainRootAndProof executes `GET /dt/v1/get-domain-root-and-proof`
func (mc *MapClient) GetDomainRootAndProof(req *ds.GetDomainRootAndProofRequest) (*ds.GetDomainRootAndProofResponse, error) {
	var resp ds.GetDomainRootAndProofResponse
	err := mc.get("dt/v1/get-domain-root-and-proof", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetConsistencyProof executes `GET /dt/v1/get-consistency-proof`
func (mc *MapClient) GetConsistencyProof(req *ds.GetConsistencyProofRequest) (*ds.GetConsistencyProofResponse, error) {
	var resp ds.GetConsistencyProofResponse
	err := mc.get("dt/v1/get-consistency-proof", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetEntries executes `GET /dt/v1/get-entries`
func (mc *MapClient) GetEntries(req *ds.GetEntriesRequest) (*ds.GetEntriesResponse, error) {
	var resp ds.GetEntriesResponse
	err := mc.get("dt/v1/get-entries", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetEntryAndProof executes `GET /dt/v1/get-entry-and-proof`
func (mc *MapClient) GetEntryAndProof(req *ds.GetEntryAndProofRequest) (*ds.GetEntryAndProofResponse, error) {
	var resp ds.GetEntryAndProofResponse
	err := mc.get("dt/v1/get-entry-and-proof", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDomainTreeIndex executes `GET /dt/v1/get-domain-tree-index`
func (mc *MapClient) GetDomainTreeIndex(req *ds.GetDomainTreeIndexRequest) (*ds.GetDomainTreeIndexResponse, error) {
	var resp ds.GetDomainTreeIndexResponse
	err := mc.get("dt/v1/get-domain-tree-index", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSourceLogs executes `GET /dt/v1/get-source-logs`
func (mc *MapClient) GetSourceLogs(req *ds.GetSourceLogsRequest) (*ds.GetSourceLogsResponse, error) {
	var resp ds.GetSourceLogsResponse
	err := mc.get("dt/v1/get-source-logs", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSourceLogAndProof executes `GET /dt/v1/get-source-log-and-proof`
func (mc *MapClient) GetSourceLogAndProof(req *ds.GetSourceLogAndProofRequest) (*ds.GetSourceLogAndProofResponse, error) {
	var resp ds.GetSourceLogAndProofResponse
	err := mc.get("dt/v1/get-source-log-and-proof", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetSourceConsistencyProof executes `GET /dt/v1/get-source-consistency-proof`
func (mc *MapClient) GetSourceConsistencyProof(req *ds.GetSourceConsistencyProofRequest) (*ds.GetSourceConsistencyProofResponse, error) {
	var resp ds.GetSourceConsistencyProofResponse
	err := mc.get("dt/v1/get-source-consistency-proof", &resp, req)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}
