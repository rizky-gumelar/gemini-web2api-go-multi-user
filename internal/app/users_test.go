package app

import (
	"context"
	"testing"
)

func TestUserMultiTenantIsolation(t *testing.T) {
	// 1. Create User A and User B
	userA, err := createUser("alice_test", "password123", "user")
	if err != nil {
		t.Fatalf("failed to create user A: %v", err)
	}
	userB, err := createUser("bob_test", "password456", "user")
	if err != nil {
		t.Fatalf("failed to create user B: %v", err)
	}

	if userA.APIKey == "" || userB.APIKey == "" {
		t.Fatalf("users should have non-empty API keys")
	}
	if userA.APIKey == userB.APIKey {
		t.Fatalf("API keys must be unique per user")
	}

	// 2. Authentication check
	uAuth, err := authenticateUser("alice_test", "password123")
	if err != nil || uAuth.ID != userA.ID {
		t.Fatalf("authentication failed for user A: %v", err)
	}

	_, err = authenticateUser("alice_test", "wrong_password")
	if err == nil {
		t.Fatalf("authentication should fail with wrong password")
	}

	// 3. API key lookup
	foundA := getUserByAPIKey(userA.APIKey)
	if foundA == nil || foundA.ID != userA.ID {
		t.Fatalf("failed to find user A by API key")
	}

	// 4. Test Cookie isolation: User A adds cookies, User B adds cookies
	cookieA := `__Secure-1PSID=alice_psid; __Secure-1PSIDTS=alice_ts; SAPISID=alice_sapisid`
	cookieB := `__Secure-1PSID=bob_psid; __Secure-1PSIDTS=bob_ts; SAPISID=bob_sapisid`

	acctAID, err := accountAddForUser(userA.ID, "Alice Account", cookieA, "")
	if err != nil {
		t.Fatalf("failed to add cookie for user A: %v", err)
	}
	acctBID, err := accountAddForUser(userB.ID, "Bob Account", cookieB, "")
	if err != nil {
		t.Fatalf("failed to add cookie for user B: %v", err)
	}
	t.Cleanup(func() {
		_ = accountDelete(acctAID)
		_ = accountDelete(acctBID)
	})

	// 5. Verify Cookie Lists are isolated
	listA := accountListForUser(userA.ID)
	if len(listA) != 1 || listA[0].Label != "Alice Account" || listA[0].UserID != userA.ID {
		t.Fatalf("user A should only see their own 1 account, got %d", len(listA))
	}

	listB := accountListForUser(userB.ID)
	if len(listB) != 1 || listB[0].Label != "Bob Account" || listB[0].UserID != userB.ID {
		t.Fatalf("user B should only see their own 1 account, got %d", len(listB))
	}

	// 6. Test pickCookieAccountForUser strict isolation
	for i := 0; i < 5; i++ {
		pickedA, okA := pickCookieAccountForUser(userA.ID)
		if !okA || pickedA == nil || pickedA.UserID != userA.ID || pickedA.Label != "Alice Account" {
			t.Fatalf("pickCookieAccountForUser(userA) returned non-Alice account: %+v", pickedA)
		}

		pickedB, okB := pickCookieAccountForUser(userB.ID)
		if !okB || pickedB == nil || pickedB.UserID != userB.ID || pickedB.Label != "Bob Account" {
			t.Fatalf("pickCookieAccountForUser(userB) returned non-Bob account: %+v", pickedB)
		}
	}

	// 7. User C with NO cookies should NEVER get User A or User B's cookies
	userC, err := createUser("charlie_test", "password789", "user")
	if err != nil {
		t.Fatalf("failed to create user C: %v", err)
	}

	if hasCookieForUser(userC.ID) {
		t.Fatalf("user C should not have cookies")
	}

	pickedC, okC := pickCookieAccountForUser(userC.ID)
	if okC || pickedC != nil {
		t.Fatalf("CRITICAL ISOLATION LEAK: user C has no cookies but picked account: %+v", pickedC)
	}

	// 8. Test Context scoping helper
	ctx := withUser(context.Background(), userA)
	uid := userFromContext(ctx)
	if uid == nil || uid.ID != userA.ID {
		t.Fatalf("userFromContext failed: expected user A, got %+v", uid)
	}
}

func TestRotateUserAPIKey(t *testing.T) {
	u, err := createUser("dave_test", "password123", "user")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	oldKey := u.APIKey
	newKey, err := rotateUserAPIKey(u.ID)
	if err != nil {
		t.Fatalf("failed to rotate API key: %v", err)
	}

	if newKey == oldKey {
		t.Fatalf("expected new key to differ from old key")
	}

	// Verify old key no longer resolves
	if getUserByAPIKey(oldKey) != nil {
		t.Fatalf("old API key should no longer be valid")
	}

	// Verify new key resolves
	found := getUserByAPIKey(newKey)
	if found == nil || found.ID != u.ID {
		t.Fatalf("new API key lookup failed")
	}
}
