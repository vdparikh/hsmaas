package hsmaas

import "testing"

func TestIsActionAllowed(t *testing.T) {
	tests := []struct {
		name   string
		policy *Policy
		action string
		want   bool
	}{
		{
			name: "allow single action",
			policy: &Policy{
				Statement: []Statement{
					{Effect: "Allow", Action: []string{"kms:Encrypt"}},
				},
			},
			action: "kms:Encrypt",
			want:   true,
		},
		{
			name: "allow one of many",
			policy: &Policy{
				Statement: []Statement{
					{Effect: "Allow", Action: []string{"kms:Encrypt", "kms:Decrypt"}},
				},
			},
			action: "kms:Decrypt",
			want:   true,
		},
		{
			name: "deny not in list",
			policy: &Policy{
				Statement: []Statement{
					{Effect: "Allow", Action: []string{"kms:Encrypt"}},
				},
			},
			action: "kms:DeleteKey",
			want:   false,
		},
		{
			name: "no statements",
			policy: &Policy{
				Statement: nil,
			},
			action: "kms:Encrypt",
			want:   false,
		},
		{
			name: "empty action list",
			policy: &Policy{
				Statement: []Statement{
					{Effect: "Allow", Action: []string{}},
				},
			},
			action: "kms:Encrypt",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsActionAllowed(tt.policy, tt.action)
			if got != tt.want {
				t.Errorf("IsActionAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
