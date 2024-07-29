package main

import (
	"database/sql"
	"log"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("postgres", "user=youruser dbname=yourdb sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}

	createPolicyTable()
}

func createPolicyTable() {
	query := `
    CREATE TABLE IF NOT EXISTS policies (
        id SERIAL PRIMARY KEY,
        key_id UUID NOT NULL,
        role VARCHAR(255) NOT NULL,
        policy JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );`
	_, err := db.Exec(query)
	if err != nil {
		log.Fatal(err)
	}
}

func fetchPolicyFromDB(keyID, role string) (*Policy, error) {
	var policy Policy
	query := "SELECT policy FROM policies WHERE key_id=$1 AND role=$2"
	err := db.QueryRow(query, keyID, role).Scan(&policy)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}
