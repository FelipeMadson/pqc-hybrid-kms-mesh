package tests

import (
	"bytes"
	"testing"
	"time"

	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/dsa"
	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/kem"
	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/kms"
	"github.com/FelipeMadson/pqc-hybrid-kms-mesh/pkg/qkd"
)

func TestHybridKEMEncapsulationDecapsulation(t *testing.T) {
	// Receiver generates keypair
	receiverPriv, err := kem.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("failed to generate hybrid keypair: %v", err)
	}

	// Sender encapsulates against receiver public key
	senderSharedSecret, ct, err := kem.Encapsulate(&receiverPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to encapsulate: %v", err)
	}

	if len(senderSharedSecret) != 32 {
		t.Fatalf("expected 32-byte shared secret, got %d", len(senderSharedSecret))
	}

	// Receiver decapsulates using private key
	receiverSharedSecret, err := kem.Decapsulate(receiverPriv, ct)
	if err != nil {
		t.Fatalf("failed to decapsulate: %v", err)
	}

	if !bytes.Equal(senderSharedSecret, receiverSharedSecret) {
		t.Fatalf("shared secrets do not match between sender and receiver")
	}
}

func TestHybridDSASignatureVerification(t *testing.T) {
	signer, err := dsa.GenerateHybridSigner()
	if err != nil {
		t.Fatalf("failed to generate signer: %v", err)
	}

	msg := []byte("RNP-SDN-FLOW-RULE:MATCH_IP_SRC_10.0.0.1_PORT_443")
	sig := signer.SignMessage(msg)

	valid, err := dsa.VerifyHybridSignature(signer.ClassicPub, signer.LatticePub, msg, sig)
	if !valid || err != nil {
		t.Fatalf("expected valid hybrid signature, got err: %v", err)
	}

	// Corrupted message check
	corrupted := []byte("RNP-SDN-FLOW-RULE:MATCH_IP_SRC_10.0.0.2_PORT_443")
	corruptValid, _ := dsa.VerifyHybridSignature(signer.ClassicPub, signer.LatticePub, corrupted, sig)
	if corruptValid {
		t.Fatalf("corrupted message validated unexpectedly")
	}
}

func TestMultidomainKMSLifecycle(t *testing.T) {
	kmsNode, err := kms.NewMultidomainKMS("pop-sp.rnp.br")
	if err != nil {
		t.Fatal(err)
	}

	// Generate key with 100ms TTL
	qkey, err := kmsNode.GenerateSessionKey("pop-rj.rnp.br", 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}

	if qkey.State != kms.StateActive {
		t.Fatalf("expected key to be active, got: %s", qkey.State)
	}

	time.Sleep(150 * time.Millisecond)
	rotated := kmsNode.RotateExpiredKeys()
	if rotated != 1 {
		t.Fatalf("expected 1 rotated key, got: %d", rotated)
	}

	if qkey.State != kms.StateExpiring {
		t.Fatalf("expected key to transition to EXPIRING, got %s", qkey.State)
	}
}

func TestETSIQKD014KeyDelivery(t *testing.T) {
	buf := qkd.NewQKDSimulatedBuffer("SAE-A", "SAE-B", 50)
	status := buf.GetStatus()
	if status.StoredKeyCount != 50 {
		t.Fatalf("expected 50 stored keys, got %d", status.StoredKeyCount)
	}

	// Request 4 keys
	keysRes, err := buf.GetEncKeys(4)
	if err != nil {
		t.Fatalf("failed to get enc keys: %v", err)
	}
	if len(keysRes.Keys) != 4 {
		t.Fatalf("expected 4 keys, got %d", len(keysRes.Keys))
	}

	// Retrieve matching decryption keys
	var ids []string
	for _, k := range keysRes.Keys {
		ids = append(ids, k.KeyID)
	}

	decRes, err := buf.GetDecKeys(ids)
	if err != nil {
		t.Fatalf("failed to get dec keys: %v", err)
	}

	for i := 0; i < 4; i++ {
		if keysRes.Keys[i].Key != decRes.Keys[i].Key {
			t.Fatalf("key material mismatch at index %d", i)
		}
	}
}
