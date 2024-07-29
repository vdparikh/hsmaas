package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/miekg/pkcs11"
)

func createKeyHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)
	key, err := createKey(session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create key"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"key_id": key})
}

func listKeysHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)

	keys, err := listKeys(session)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list keys"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"keys": keys})
}

func getKeyHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)
	keyID := c.Param("key_id")

	key, err := fetchKey(session, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Key not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"key": key})
}

func deleteKeyHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)
	keyID := c.Param("key_id")

	err := deleteKey(session, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Key deleted"})
}

func rotateKeyHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)
	keyID := c.Param("key_id")

	newKey, err := rotateKey(session, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to rotate key"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"new_key_id": newKey})
}

func encryptHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)
	keyID := c.Param("key_id")
	plaintext := c.PostForm("plaintext")

	key, err := fetchKey(session, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Key not found"})
		return
	}

	iv, ciphertext, err := encryptData(session, key, []byte(plaintext))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"iv": iv, "ciphertext": ciphertext})
}

func decryptHandler(c *gin.Context) {
	session := c.MustGet("session").(pkcs11.SessionHandle)
	keyID := c.Param("key_id")
	iv := c.PostForm("iv")
	ciphertext := c.PostForm("ciphertext")

	key, err := fetchKey(session, keyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Key not found"})
		return
	}

	plaintext, err := decryptData(session, key, []byte(iv), []byte(ciphertext))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Decryption failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"plaintext": plaintext})
}

// fetchKey retrieves a key from the HSM based on the key ID
func fetchKey(session pkcs11.SessionHandle, keyID string) (pkcs11.ObjectHandle, error) {
	// Define the template to search for the key
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, []byte(keyID)),
	}

	// Initialize the search
	err := p.FindObjectsInit(session, template)
	if err != nil {
		log.Printf("FindObjectsInit error: %v", err)
		return 0, err
	}
	defer p.FindObjectsFinal(session)

	// Search for the key object
	handles, _, err := p.FindObjects(session, 1)
	if err != nil {
		log.Printf("FindObjects error: %v", err)
		return 0, err
	}

	if len(handles) == 0 {
		log.Printf("No key found for ID: %s", keyID)
		return 0, pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID)
	}

	// Return the first found key handle
	return handles[0], nil
}
