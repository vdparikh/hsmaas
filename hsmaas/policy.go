package hsmaas

// Policy represents a key policy document (e.g. AWS KMS-style).
type Policy struct {
	Version   string      `json:"Version"`
	Statement []Statement `json:"Statement"`
}

// Statement is a single policy statement (Allow/Deny and actions).
type Statement struct {
	Effect    string    `json:"Effect"`
	Principal Principal `json:"Principal"`
	Action    []string  `json:"Action"`
	Resource  string    `json:"Resource"`
}

// Principal identifies who the statement applies to (e.g. IAM user ARN).
type Principal struct {
	AWS string `json:"AWS"`
}

// IsActionAllowed reports whether the policy allows the given action.
func IsActionAllowed(policy *Policy, action string) bool {
	for _, stmt := range policy.Statement {
		if stmt.Effect == "Allow" && containsAction(stmt.Action, action) {
			return true
		}
	}
	return false
}

func containsAction(actions []string, action string) bool {
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}
