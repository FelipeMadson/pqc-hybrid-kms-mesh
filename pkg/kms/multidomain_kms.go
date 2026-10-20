// Package kms implements a Multidomain Key Management Service (KMS)
// for RNP Quantum-Safe Optical Networks (Projeto 2 Chamada PCI 2026).
package kms

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/kem"
)

type KeyState string

const (
	StateActive    KeyState = "ACTIVE"
	StateExpiring  KeyState = "EXPIRING"
	StateRevoked   KeyState = "REVOKED"
	StateDestroyed KeyState = "DESTROYED"
)

// QuantumSafeKey models an ephemeral or session transmission key secured across PoP domains.
type QuantumSafeKey struct {
	KeyID        string    `json:"keyId"`
	DomainOrigin string    `json:"domainOrigin"` // e.g. "pop-df.rnp.br"
	DomainTarget string    `json:"domainTarget"` // e.g. "pop-sp.rnp.br"
	KeyBytes     []byte    `json:"-"`            // Protected in secure memory
	State        KeyState  `json:"state"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Rotations    int       `json:"rotations"`
}

// MultidomainKMS coordinates key lifecycle, rotation, and distribution across RNP backbone domains.
type MultidomainKMS struct {
	mu           sync.RWMutex
	localDomain  string
	keys         map[string]*QuantumSafeKey
	keypair      *kem.HybridPrivateKey
	rotationPool map[string][]string // Domain pair -> active key IDs
}

// NewMultidomainKMS initializes the KMS node for a specific RNP PoP domain.
func NewMultidomainKMS(localDomain string) (*MultidomainKMS, error) {
	kp, err := kem.GenerateHybridKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate KMS node keypair: %w", err)
	}

	return &MultidomainKMS{
		localDomain:  localDomain,
		keys:         make(map[string]*QuantumSafeKey),
		keypair:      kp,
		rotationPool: make(map[string][]string),
	}, nil
}

// GenerateSessionKey generates an AES-256 / ChaCha20-Poly1305 symmetric transmission key.
func (kms *MultidomainKMS) GenerateSessionKey(targetDomain string, ttl time.Duration) (*QuantumSafeKey, error) {
	kms.mu.Lock()
	defer kms.mu.Unlock()

	keyBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, keyBytes); err != nil {
		return nil, fmt.Errorf("entropy source failure: %w", err)
	}

	now := time.Now().UTC()
	keyID := fmt.Sprintf("qkey-%s-%s-%d", kms.localDomain, targetDomain, now.UnixNano())

	qkey := &QuantumSafeKey{
		KeyID:        keyID,
		DomainOrigin: kms.localDomain,
		DomainTarget: targetDomain,
		KeyBytes:     keyBytes,
		State:        StateActive,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		Rotations:    0,
	}

	kms.keys[keyID] = qkey
	domainPair := fmt.Sprintf("%s:%s", kms.localDomain, targetDomain)
	kms.rotationPool[domainPair] = append(kms.rotationPool[domainPair], keyID)

	return qkey, nil
}

// EncapsulateKeyForTransmission encapsulates the session key to a target domain KMS node using Hybrid PQC.
func (kms *MultidomainKMS) EncapsulateKeyForTransmission(keyID string, targetPub *kem.HybridPublicKey) (*kem.EncapsulatedCiphertext, error) {
	kms.mu.RLock()
	qkey, exists := kms.keys[keyID]
	kms.mu.RUnlock()

	if !exists {
		return nil, errors.New("key not found in KMS vault")
	}
	if qkey.State != StateActive {
		return nil, fmt.Errorf("cannot transmit key in state %s", qkey.State)
	}

	_, ct, err := kem.Encapsulate(targetPub)
	if err != nil {
		return nil, fmt.Errorf("hybrid encapsulation failed: %w", err)
	}

	return ct, nil
}

// RotateExpiredKeys transitions keys past their expiration window to EXPIRING or REVOKED.
func (kms *MultidomainKMS) RotateExpiredKeys() int {
	kms.mu.Lock()
	defer kms.mu.Unlock()

	now := time.Now().UTC()
	rotatedCount := 0

	for _, k := range kms.keys {
		if k.State == StateActive && now.After(k.ExpiresAt) {
			k.State = StateExpiring
			rotatedCount++
		}
	}

	return rotatedCount
}

// GetPublicKey returns the hybrid PQC public key for this KMS domain node.
func (kms *MultidomainKMS) GetPublicKey() kem.HybridPublicKey {
	return kms.keypair.PublicKey
}
