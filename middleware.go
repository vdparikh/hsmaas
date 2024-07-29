package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func PolicyMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Acquire a session from the pool
		session := sessionPool.Acquire()
		defer sessionPool.Release(session)

		// Store the session in the context
		c.Set("session", session)

		// Extract user info and action from context
		user := c.GetString("user")
		action := c.GetString("action")
		keyID := c.GetString("key_id")

		// Fetch the policy from the database
		policy, err := fetchPolicyFromDB(keyID, user)
		if err != nil || policy == nil {
			c.JSON(http.StatusForbidden, gin.H{"error": "No policy found"})
			c.Abort()
			return
		}

		// Check if action is allowed
		if !isActionAllowed(policy, action) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Action not allowed"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func isActionAllowed(policy *Policy, action string) bool {
	for _, stmt := range policy.Statement {
		if stmt.Effect == "Allow" && contains(stmt.Action, action) {
			return true
		}
	}
	return false
}

func contains(actions []string, action string) bool {
	for _, a := range actions {
		if a == action {
			return true
		}
	}
	return false
}
