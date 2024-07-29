package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/miekg/pkcs11"
)

// softhsm2-util --init-token --slot 0 --label "MyKEKLabel" --pin 1234 --so-pin 0000
// softhsm2-util --init-token --slot 5 --label "MyKEKLabel" --pin 1234 --so-pin 0000
// The token has been initialized and is reassigned to slot 868617254

var (
	p           *pkcs11.Ctx
	libraryPath = "/opt/homebrew/lib/softhsm/libsofthsm2.so"
	slotLabel   = "ForKMS"
	keyLabel    = "MyKEKLabel"
	hsmPin      = "1234"
	sessionPool *SessionPool
	poolSize    = 10
)

func initHSM() {
	p = pkcs11.New(libraryPath)
	err := p.Initialize()
	if err != nil {
		log.Fatalf("Failed to initialize PKCS#11 module: %v", err)
	}

	slot, err := findSlotByLabel(slotLabel)
	if err != nil {
		log.Fatalf("Failed to find slot by label: %v", err)
	}

	sessionPool = NewSessionPool(p, slot, hsmPin, poolSize)
}

func closeHSM() {
	sessionPool.Close()
	p.Finalize()
}

func findSlotByLabel(slotLabel string) (uint, error) {
	slots, err := p.GetSlotList(true)
	if err != nil {
		return 0, err
	}

	for _, slot := range slots {
		info, err := p.GetSlotInfo(slot)
		if err != nil {
			return 0, err
		}
		if info.SlotDescription == slotLabel {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("slot with label %s not found", slotLabel)
}

func createKey(session pkcs11.SessionHandle) (pkcs11.ObjectHandle, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),
		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	}
	return p.GenerateKey(session, mechanism, template)
}

func listKeys(session pkcs11.SessionHandle) ([]pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	}

	err := p.FindObjectsInit(session, template)
	if err != nil {
		return nil, err
	}
	defer p.FindObjectsFinal(session)

	var handles []pkcs11.ObjectHandle
	for {
		objs, _, err := p.FindObjects(session, 100)
		if err != nil {
			return nil, err
		}
		if len(objs) == 0 {
			break
		}
		handles = append(handles, objs...)
	}

	return handles, nil
}

func deleteKey(session pkcs11.SessionHandle, keyID string) error {
	key, err := fetchKey(session, keyID)
	if err != nil {
		return err
	}

	err = p.DestroyObject(session, key)
	if err != nil {
		return err
	}

	return nil
}

func rotateKey(session pkcs11.SessionHandle, keyID string) (pkcs11.ObjectHandle, error) {
	oldKey, err := fetchKey(session, keyID)
	if err != nil {
		return 0, err
	}

	newKey, err := createKey(session)
	if err != nil {
		return 0, err
	}

	err = p.DestroyObject(session, oldKey)
	if err != nil {
		return 0, err
	}

	return newKey, nil
}

func generateIV() ([]byte, error) {
	iv := make([]byte, 16) // Assuming AES block size of 16 bytes
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}
	return iv, nil
}

func encryptData(session pkcs11.SessionHandle, key pkcs11.ObjectHandle, plaintext []byte) ([]byte, []byte, error) {
	iv, err := generateIV()
	if err != nil {
		return nil, nil, err
	}

	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}
	err = p.EncryptInit(session, mechanism, key)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := p.Encrypt(session, plaintext)
	if err != nil {
		return nil, nil, err
	}
	return iv, ciphertext, nil
}

func decryptData(session pkcs11.SessionHandle, key pkcs11.ObjectHandle, iv, ciphertext []byte) ([]byte, error) {
	mechanism := []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC_PAD, iv)}
	err := p.DecryptInit(session, mechanism, key)
	if err != nil {
		return nil, err
	}

	plaintext, err := p.Decrypt(session, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
