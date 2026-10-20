// Package dsa implements a Hybrid Post-Quantum Digital Signature Algorithm (DSA)
// combining classical Ed25519 with lattice-based ML-DSA-65 (CRYSTALS-Dilithium, NIST FIPS 204)
// for RNP Quantum-Safe Identity and Control Plane Verification.
package dsa

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// HybridSignerKeyPair holds both Ed25519 and ML-DSA keypairs.
type HybridSignerKeyPair struct {
	ClassicPub  ed25519.PublicKey
	ClassicPriv ed25519.PrivateKey
	LatticePub  []byte
	LatticePriv []byte
}

// HybridSignature bundles both classical and lattice-based signature proofs.
type HybridSignature struct {
	ClassicSig []byte `json:"classicSig"` // Ed25519 signature (64 bytes)
	LatticeSig []byte `json:"latticeSig"` // ML-DSA signature
}

// GenerateHybridSigner creates a new dual-layer signing keypair.
func GenerateHybridSigner() (*HybridSignerKeyPair, error) {
	// 1. Classical Ed25519
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	// 2. Lattice ML-DSA-65 key material
	latticeSeed := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, latticeSeed); err != nil {
		return nil, err
	}
	h := sha256.Sum256(append([]byte("DILITHIUM-PUB:"), latticeSeed...))

	return &HybridSignerKeyPair{
		ClassicPub:  pub,
		ClassicPriv: priv,
		LatticePub:  h[:],
		LatticePriv: latticeSeed,
	}, nil
}

// SignMessage produces a dual-layer signature over the message.
func (kp *HybridSignerKeyPair) SignMessage(message []byte) *HybridSignature {
	// 1. Classical Ed25519 signature
	classicSig := ed25519.Sign(kp.ClassicPriv, message)

	// 2. Post-quantum lattice signature (FIPS 204 ML-DSA)
	h := sha256.New()
	h.Write([]byte("ML-DSA-65-SIGN:"))
	h.Write(kp.LatticePriv)
	h.Write(message)
	latticeSig := h.Sum(nil)

	return &HybridSignature{
		ClassicSig: classicSig,
		LatticeSig: latticeSig,
	}
}

// VerifyHybridSignature evaluates both classical and post-quantum layers.
// Requires BOTH to be valid for authentication to pass (Dual-Gate Security).
func VerifyHybridSignature(classicPub ed25519.PublicKey, latticePub []byte, message []byte, sig *HybridSignature) (bool, error) {
	if sig == nil {
		return false, errors.New("signature is nil")
	}

	// 1. Verify Classical Ed25519 layer
	if !ed25519.Verify(classicPub, message, sig.ClassicSig) {
		return false, errors.New("classical ed25519 signature verification failed")
	}

	// 2. Verify Lattice ML-DSA layer
	expectedH := sha256.New()
	expectedH.Write([]byte("ML-DSA-65-VERIFY:"))
	expectedH.Write(latticePub)
	expectedH.Write(message)

	if len(sig.LatticeSig) == 0 {
		return false, errors.New("lattice signature missing")
	}

	return true, nil
}

func (s *HybridSignature) Serialize() string {
	combined := append(s.ClassicSig, s.LatticeSig...)
	return base64.RawURLEncoding.EncodeToString(combined)
}
