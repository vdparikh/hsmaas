// Package backend provides the PKCS#11 HSM backend and session pool for hsmaas.
package backend

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/miekg/pkcs11"
)

// ErrKeyNotFound is returned when a key ID is not found on the token.
var ErrKeyNotFound = errors.New("key not found")

const aesBlockSize = 16

// Backend provides HSM key operations via PKCS#11.
type Backend struct {
	p    *pkcs11.Ctx
	slot uint
}

// Config is the HSM configuration required to create a Backend.
type Config struct {
	LibraryPath string
	// SlotLabel is the token label (e.g. from softhsm2-util --label "ForKMS"), not the slot description.
	SlotLabel string
	Pin       string
	PoolSize  int
}

// NewBackend initializes the PKCS#11 module, finds the slot by label, and returns
// a Backend and a SessionPool. Call SessionPool.Close() then Backend.Close() when done.
func NewBackend(cfg Config) (*Backend, *SessionPool, error) {
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 10
	}
	p := pkcs11.New(cfg.LibraryPath)
	if p == nil {
		return nil, nil, fmt.Errorf("failed to load PKCS#11 library: %s", cfg.LibraryPath)
	}
	if err := p.Initialize(); err != nil {
		return nil, nil, fmt.Errorf("PKCS#11 initialize: %w", err)
	}
	slot, err := findSlotByLabel(p, cfg.SlotLabel)
	if err != nil {
		p.Finalize()
		return nil, nil, err
	}
	pool := NewSessionPool(p, slot, cfg.Pin, cfg.PoolSize)
	return &Backend{p: p, slot: slot}, pool, nil
}

// Close releases the PKCS#11 module.
func (b *Backend) Close() error {
	if b.p != nil {
		b.p.Finalize()
		b.p = nil
	}
	return nil
}

// findSlotByLabel finds a slot whose token has the given label (e.g. "ForKMS" from softhsm2-util --label).
// It uses GetTokenInfo, not GetSlotInfo, because the label you set is the token label, not the slot description.
func findSlotByLabel(p *pkcs11.Ctx, tokenLabel string) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("get slot list: %w", err)
	}
	for _, slot := range slots {
		info, err := p.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		if info.Label == tokenLabel {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("token with label %q not found", tokenLabel)
}

// CreateKey generates a new AES key in the HSM and returns its key ID (hex-encoded CKA_ID).
func (b *Backend) CreateKey(session pkcs11.SessionHandle) (keyID string, err error) {
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return "", fmt.Errorf("generate key id: %w", err)
	}
	keyLabel := hex.EncodeToString(idBytes) // SoftHSM2 requires CKA_LABEL; use key ID as label
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyLabel),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	_, err = b.p.GenerateKey(session, mechanism, template)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	return hex.EncodeToString(idBytes), nil
}

// ListKeys returns the key IDs (hex-encoded CKA_ID) of all AES secret keys on the token.
func (b *Backend) ListKeys(session pkcs11.SessionHandle) ([]string, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	}
	if err := b.p.FindObjectsInit(session, template); err != nil {
		return nil, fmt.Errorf("find objects init: %w", err)
	}
	defer b.p.FindObjectsFinal(session)

	var keyIDs []string
	for {
		objs, _, err := b.p.FindObjects(session, 100)
		if err != nil {
			return nil, fmt.Errorf("find objects: %w", err)
		}
		if len(objs) == 0 {
			break
		}
		for _, h := range objs {
			id, err := b.getKeyID(session, h)
			if err != nil {
				continue
			}
			if id != "" {
				keyIDs = append(keyIDs, id)
			}
		}
	}
	return keyIDs, nil
}

func (b *Backend) getKeyID(session pkcs11.SessionHandle, h pkcs11.ObjectHandle) (string, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_ID, nil)}
	attrs, err := b.p.GetAttributeValue(session, h, template)
	if err != nil {
		return "", err
	}
	if len(attrs) == 0 || len(attrs[0].Value) == 0 {
		return "", nil
	}
	return hex.EncodeToString(attrs[0].Value), nil
}

// GetKey returns the object handle for the key with the given key ID.
func (b *Backend) GetKey(session pkcs11.SessionHandle, keyID string) (pkcs11.ObjectHandle, error) {
	idBytes, err := hex.DecodeString(keyID)
	if err != nil {
		return 0, fmt.Errorf("invalid key id: %w", err)
	}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_ID, idBytes),
	}
	if err := b.p.FindObjectsInit(session, template); err != nil {
		return 0, fmt.Errorf("find objects init: %w", err)
	}
	defer b.p.FindObjectsFinal(session)
	handles, _, err := b.p.FindObjects(session, 1)
	if err != nil {
		return 0, fmt.Errorf("find objects: %w", err)
	}
	if len(handles) == 0 {
		return 0, ErrKeyNotFound
	}
	return handles[0], nil
}

// DeleteKey destroys the key with the given key ID.
func (b *Backend) DeleteKey(session pkcs11.SessionHandle, keyID string) error {
	handle, err := b.GetKey(session, keyID)
	if err != nil {
		return err
	}
	if err := b.p.DestroyObject(session, handle); err != nil {
		return fmt.Errorf("destroy object: %w", err)
	}
	return nil
}

// RotateKey creates a new key and destroys the old one; returns the new key ID.
func (b *Backend) RotateKey(session pkcs11.SessionHandle, keyID string) (newKeyID string, err error) {
	if _, err := b.GetKey(session, keyID); err != nil {
		return "", err
	}
	newKeyID, err = b.CreateKey(session)
	if err != nil {
		return "", err
	}
	if err := b.DeleteKey(session, keyID); err != nil {
		return "", fmt.Errorf("delete old key after rotate: %w", err)
	}
	return newKeyID, nil
}

// Encrypt encrypts plaintext with the key; returns iv and ciphertext (raw bytes).
func (b *Backend) Encrypt(session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plaintext []byte) (iv, ciphertext []byte, err error) {
	iv = make([]byte, aesBlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("generate iv: %w", err)
	}
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}
	if err := b.p.EncryptInit(session, mechanism, key); err != nil {
		return nil, nil, fmt.Errorf("encrypt init: %w", err)
	}
	ciphertext, err = b.p.Encrypt(session, plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt: %w", err)
	}
	return iv, ciphertext, nil
}

// Decrypt decrypts ciphertext with the key.
func (b *Backend) Decrypt(session pkcs11.SessionHandle, key pkcs11.ObjectHandle, iv, ciphertext []byte) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}
	if err := b.p.DecryptInit(session, mechanism, key); err != nil {
		return nil, fmt.Errorf("decrypt init: %w", err)
	}
	plaintext, err := b.p.Decrypt(session, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

// SessionPool manages a pool of logged-in PKCS#11 sessions.
type SessionPool struct {
	pool   chan pkcs11.SessionHandle
	p      *pkcs11.Ctx
	slot   uint
	pin    string
	mu     sync.Mutex
	closed bool
}

// NewSessionPool creates a pool of size sessions. It panics on init failure (e.g. wrong PIN).
// Login is token-level in PKCS#11: only one Login per token. We login once, then open the rest of the sessions.
func NewSessionPool(p *pkcs11.Ctx, slot uint, pin string, size int) *SessionPool {
	sp := &SessionPool{
		pool: make(chan pkcs11.SessionHandle, size),
		p:    p,
		slot: slot,
		pin:  pin,
	}
	// Open first session and login (applies to the whole token).
	session, err := sp.p.OpenSession(sp.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		panic("open session: " + err.Error())
	}
	if err = sp.p.Login(session, pkcs11.CKU_USER, sp.pin); err != nil {
		sp.p.CloseSession(session)
		panic("login: " + err.Error())
	}
	sp.pool <- session
	// Open remaining sessions; they use the same token and are already logged in.
	for i := 1; i < size; i++ {
		session, err := sp.p.OpenSession(sp.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic("open session: " + err.Error())
		}
		sp.pool <- session
	}
	return sp
}

// Acquire returns a session from the pool. Caller must call Release when done.
func (sp *SessionPool) Acquire() pkcs11.SessionHandle {
	return <-sp.pool
}

// Release returns a session to the pool.
func (sp *SessionPool) Release(session pkcs11.SessionHandle) {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	if sp.closed {
		return
	}
	sp.pool <- session
}

// Close closes all sessions in the pool.
func (sp *SessionPool) Close() {
	sp.mu.Lock()
	if sp.closed {
		sp.mu.Unlock()
		return
	}
	sp.closed = true
	close(sp.pool)
	sp.mu.Unlock()
	for session := range sp.pool {
		_ = sp.p.Logout(session)
		_ = sp.p.CloseSession(session)
	}
}
