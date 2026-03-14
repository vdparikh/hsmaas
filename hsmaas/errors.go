package hsmaas

import "errors"

// Sentinel errors for programmatic handling.
var (
	ErrPolicyNotFound = errors.New("hsmaas: policy not found")
	ErrActionDenied   = errors.New("hsmaas: action not allowed by policy")
	ErrKeyNotFound    = errors.New("hsmaas: key not found")
)
