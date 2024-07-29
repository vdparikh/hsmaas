# HSM as a Service 
This project implements a Key Management System (KMS) using the MCloud HSM, the Gin web framework, and a PostgreSQL database. The KMS provides secure key management functionalities similar to AWS KMS, including key creation, retrieval, deletion, rotation, and data encryption/decryption.

## Features

- **Centralized Key Management**: Manage all encryption keys in a single place.
- **Key Policies and Access Control**: Implement fine-grained policies for key usage.
- **Encryption and Decryption**: Securely handle data encryption and decryption.
- **Audit Logging and Monitoring**: Log all key management operations.
- **Automated Key Rotation**: Support automatic rotation of keys.
- **High Availability and Scalability**: Ensure the system is highly available and scalable.

## Prerequisites

- Go 1.16+
- PostgreSQL
- Cloud HSM with support for PKCS#11 library
- Git

## Setup

### 1. Clone the Repository

```bash
git clone https://github.com/vdparikh/hsmaas.git
cd hsmaas
```

### 2. Install Dependencies

```bash
go mod tidy
```

### 3. Configure PostgreSQL

Ensure PostgreSQL is installed and running. Update the `db.go` file with your PostgreSQL connection details.

```go
const (
    host     = "localhost"
    port     = 5432
    user     = "youruser"
    password = "yourpassword"
    dbname   = "yourdb"
)
```

### 4. Configure HSM

Update the `hsm.go` file with the path to your PKCS#11 library.


#### Install Soft HSM on your Mac
```
brew install softhsm

mkdir ~/softhsm-tokens
directories.tokendir = /Users/yourusername/softhsm-tokens
softhsm2-util --init-token --slot 0 --label "MyToken" --pin 1234 --so-pin 0000
```


--slot 0 specifies the slot where the token will be initialized. If you're initializing the first token, slot 0 is typically used.
--label "MyToken" sets a label for the token, which you'll use to reference it.
--pin 1234 sets the user PIN for the token, used for user operations. You should change 1234 to a secure PIN.
--so-pin 0000 sets the Security Officer (SO) PIN, used for administrative operations. Change 0000 to a secure PIN as well.


```
softhsm2-util --init-token --slot 4 --label "MyToken" --pin 1234 --so-pin 0000
The token has been initialized and is reassigned to slot 1191770593

```


```go
p = pkcs11.New("/opt/homebrew/lib/softhsm/libsofthsm2.so")
```

### 5. Run the Server

```bash
go run main.go
```

## API Endpoints

### Create Key

```
POST /create-key
```
Creates a new encryption key.

### List Keys

```
GET /list-keys
```
Lists all existing keys.

### Get Key

```
GET /get-key/:key_id
```
Retrieves details of a specific key by its ID.

### Delete Key

```
DELETE /delete-key/:key_id
```
Deletes a specific key by its ID.

### Rotate Key

```
POST /rotate-key/:key_id
```
Rotates (replaces) a specific key by its ID.

### Encrypt Data

```
POST /encrypt/:key_id
```
Encrypts data using a specific key.

**Request Parameters:**

- `plaintext` (form-data): Data to be encrypted.

**Response:**

- `iv`: Initialization vector used for encryption.
- `ciphertext`: Encrypted data.

### Decrypt Data

```
POST /decrypt/:key_id
```
Decrypts data using a specific key.

**Request Parameters:**

- `iv` (form-data): Initialization vector used during encryption.
- `ciphertext` (form-data): Data to be decrypted.

**Response:**

- `plaintext`: Decrypted data.

## Middleware

### Policy Middleware

The policy middleware ensures that only authorized users can perform operations on keys based on predefined policies.

### Example Policy Document

```json
{
    "Version": "2024-07-29",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:user/Alice"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt"
            ],
            "Resource": "*"
        }
    ]
}
```





## License

This project is licensed under the MIT License.

## Acknowledgements

- [Gin Web Framework](https://github.com/gin-gonic/gin)
- [miekg/pkcs11](https://github.com/miekg/pkcs11)
