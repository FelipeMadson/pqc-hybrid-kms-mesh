// Package qkd implements the ETSI GS QKD 014 standard REST interface
// for Quantum Key Distribution Key Management Systems in the RNP network.
package qkd

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// KeyBufferStatus reflects the state of the ETSI QKD 014 key buffer between two Secure Application Entities (SAE).
type KeyBufferStatus struct {
	SourceSAEID      string `json:"source_sae_id"`
	TargetSAEID      string `json:"target_sae_id"`
	StoredKeyCount   int    `json:"stored_key_count"`
	MaxKeyCount      int    `json:"max_key_count"`
	KeySizeBits      int    `json:"key_size_bits"`
	MaxKeyPerRequest int    `json:"max_key_per_request"`
	MinKeyPerRequest int    `json:"min_key_per_request"`
}

// KeyContainer represents an individual key delivered via ETSI QKD 014.
type KeyContainer struct {
	KeyID string `json:"key_ID"`
	Key   string `json:"key"` // Base64 encoded key material
}

// KeyResponse encapsulates the key delivery conforming to ETSI GS QKD 014.
type KeyResponse struct {
	Keys []KeyContainer `json:"keys"`
}

// QKDSimulatedBuffer simulates a hardware QKD link (e.g. BB84 / Decoy-State QKD)
// producing quantum randomness and delivering keys through the standardized API.
type QKDSimulatedBuffer struct {
	mu           sync.RWMutex
	sourceSAE    string
	targetSAE    string
	keyStore     map[string][]byte
	storedCount  int
	maxKeys      int
	keySizeBits  int
}

// NewQKDSimulatedBuffer initializes the QKD buffer.
func NewQKDSimulatedBuffer(sourceSAE, targetSAE string, initialKeyCount int) *QKDSimulatedBuffer {
	buf := &QKDSimulatedBuffer{
		sourceSAE:   sourceSAE,
		targetSAE:   targetSAE,
		keyStore:    make(map[string][]byte),
		maxKeys:     10000,
		keySizeBits: 256,
	}
	buf.replenish(initialKeyCount)
	return buf
}

// GetStatus returns the current ETSI 014 key buffer status.
func (b *QKDSimulatedBuffer) GetStatus() KeyBufferStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()

	return KeyBufferStatus{
		SourceSAEID:      b.sourceSAE,
		TargetSAEID:      b.targetSAE,
		StoredKeyCount:   len(b.keyStore),
		MaxKeyCount:      b.maxKeys,
		KeySizeBits:      b.keySizeBits,
		MaxKeyPerRequest: 64,
		MinKeyPerRequest: 1,
	}
}

// GetEncKeys delivers new quantum keys for encryption (Master SAE endpoint).
func (b *QKDSimulatedBuffer) GetEncKeys(number int) (*KeyResponse, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if number <= 0 || number > 64 {
		return nil, errors.New("requested key count must be between 1 and 64")
	}

	res := &KeyResponse{Keys: make([]KeyContainer, 0, number)}
	for i := 0; i < number; i++ {
		keyBytes := make([]byte, b.keySizeBits/8)
		if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
			return nil, err
		}
		keyID := fmt.Sprintf("qkd-%s-%s-%d-%d", b.sourceSAE, b.targetSAE, time.Now().UnixNano(), i)
		b.keyStore[keyID] = keyBytes

		res.Keys = append(res.Keys, KeyContainer{
			KeyID: keyID,
			Key:   base64.StdEncoding.EncodeToString(keyBytes),
		})
	}

	return res, nil
}

// GetDecKeys delivers existing quantum keys matching the requested key IDs (Slave SAE endpoint).
func (b *QKDSimulatedBuffer) GetDecKeys(keyIDs []string) (*KeyResponse, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	res := &KeyResponse{Keys: make([]KeyContainer, 0, len(keyIDs))}
	for _, id := range keyIDs {
		k, exists := b.keyStore[id]
		if !exists {
			return nil, fmt.Errorf("qkd key '%s' not found or already consumed", id)
		}
		res.Keys = append(res.Keys, KeyContainer{
			KeyID: id,
			Key:   base64.StdEncoding.EncodeToString(k),
		})
	}

	return res, nil
}

func (b *QKDSimulatedBuffer) replenish(count int) {
	for i := 0; i < count; i++ {
		k := make([]byte, 32)
		_, _ = io.ReadFull(rand.Reader, k)
		id := fmt.Sprintf("pre-seed-qkd-%d", i)
		b.keyStore[id] = k
	}
}
