package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

func main() {
	initDB()
	initHSM()
	defer closeHSM()

	r := gin.Default()

	r.Use(gin.BasicAuth(gin.Accounts{
		"admin": "password",
	}))

	r.Use(PolicyMiddleware())

	r.POST("/create-key", createKeyHandler)
	r.GET("/list-keys", listKeysHandler)
	r.GET("/get-key/:key_id", getKeyHandler)
	r.DELETE("/delete-key/:key_id", deleteKeyHandler)
	r.POST("/rotate-key/:key_id", rotateKeyHandler)
	r.POST("/encrypt/:key_id", encryptHandler)
	r.POST("/decrypt/:key_id", decryptHandler)

	go func() {
		if err := r.Run(":8080"); err != nil {
			log.Fatalf("Failed to run server: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
}
