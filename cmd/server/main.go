// Command server starts the PQC-Hybrid-KMS microservice daemon for RNP Quantum-Safe Networks.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/dsa"
	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/kem"
	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/kms"
	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/qkd"
)

type Server struct {
	kmsNode   *kms.MultidomainKMS
	qkdBuffer *qkd.QKDSimulatedBuffer
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8085"
	}

	kmsNode, err := kms.NewMultidomainKMS("pop-df.rnp.br")
	if err != nil {
		log.Fatalf("failed to init KMS node: %v", err)
	}

	qkdBuffer := qkd.NewQKDSimulatedBuffer("SAE-PoP-DF", "SAE-PoP-SP", 100)

	srv := &Server{
		kmsNode:   kmsNode,
		qkdBuffer: qkdBuffer,
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", srv.handleHealth)
	mux.HandleFunc("GET /api/v1/pqc/status", srv.handleStatus)
	mux.HandleFunc("GET /api/v1/pqc/public-key", srv.handlePublicKey)

	// ETSI GS QKD 014 REST Endpoints
	mux.HandleFunc("GET /api/v1/keys/status", srv.handleQKDStatus)
	mux.HandleFunc("GET /api/v1/keys/enc_keys", srv.handleQKDEncKeys)
	mux.HandleFunc("POST /api/v1/keys/dec_keys", srv.handleQKDDecKeys)

	// Dual-Layer KEM Operations
	mux.HandleFunc("POST /api/v1/kem/encapsulate", srv.handleKEMEncapsulate)

	log.Printf("[PQC-KMS] Listening on http://0.0.0.0:%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatalf("server terminated: %v", err)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "pqc-hybrid-kms-mesh",
		"version":   "1.0.0",
		"pqcSuites": []string{"NIST FIPS 203 (ML-KEM-768)", "NIST FIPS 204 (ML-DSA-65)", "ETSI GS QKD 014"},
		"domain":    "pop-df.rnp.br",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, map[string]interface{}{
		"domain":    "pop-df.rnp.br",
		"qkdStatus": s.qkdBuffer.GetStatus(),
	})
}

func (s *Server) handlePublicKey(w http.ResponseWriter, r *http.Request) {
	pub := s.kmsNode.GetPublicKey()
	respond(w, http.StatusOK, map[string]interface{}{
		"classicPub": base64.StdEncoding.EncodeToString(pub.ClassicPub),
		"latticePub": base64.StdEncoding.EncodeToString(pub.LatticePub),
		"algorithm":  "X25519 + ML-KEM-768 (Dual-Layer Hybrid)",
	})
}

func (s *Server) handleQKDStatus(w http.ResponseWriter, r *http.Request) {
	respond(w, http.StatusOK, s.qkdBuffer.GetStatus())
}

func (s *Server) handleQKDEncKeys(w http.ResponseWriter, r *http.Request) {
	numStr := r.URL.Query().Get("number")
	number := 1
	if numStr != "" {
		if n, err := strconv.Atoi(numStr); err == nil && n > 0 {
			number = n
		}
	}

	keys, err := s.qkdBuffer.GetEncKeys(number)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	respond(w, http.StatusOK, keys)
}

func (s *Server) handleQKDDecKeys(w http.ResponseWriter, r *http.Request) {
	var body struct {
		KeyIDs []string `json:"key_IDs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	keys, err := s.qkdBuffer.GetDecKeys(body.KeyIDs)
	if err != nil {
		respond(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}
	respond(w, http.StatusOK, keys)
}

func (s *Server) handleKEMEncapsulate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ClassicPub string `json:"classicPub"`
		LatticePub string `json:"latticePub"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}

	classicB, err := base64.StdEncoding.DecodeString(body.ClassicPub)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "invalid classicPub base64"})
		return
	}
	latticeB, err := base64.StdEncoding.DecodeString(body.LatticePub)
	if err != nil {
		respond(w, http.StatusBadRequest, map[string]string{"error": "invalid latticePub base64"})
		return
	}

	pub := &kem.HybridPublicKey{
		ClassicPub: classicB,
		LatticePub: latticeB,
	}

	secret, ct, err := kem.Encapsulate(pub)
	if err != nil {
		respond(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respond(w, http.StatusOK, map[string]interface{}{
		"sharedSecretHex": fmt.Sprintf("%x", secret),
		"ciphertext": map[string]string{
			"classicEphemeralPub": base64.StdEncoding.EncodeToString(ct.ClassicEphemeralPub),
			"latticeCiphertext":   base64.StdEncoding.EncodeToString(ct.LatticeCiphertext),
		},
	})
}

func respond(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
