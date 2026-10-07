package db

import "testing"

func TestAuthUserApprovalLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	defer d.Close()
	providerID := "oauth-test-user-approval"
	_, _ = d.Exec(`DELETE FROM auth_users WHERE provider='google' AND provider_id=$1`, providerID)
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM auth_users WHERE provider='google' AND provider_id=$1`, providerID) })
	u, err := d.UpsertGoogleUser(providerID, "OAuth-Test@Example.com", "OAuth Test", "")
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "pending" || u.Role != "user" || u.Email != "oauth-test@example.com" {
		t.Fatalf("new user=%#v", u)
	}
	u, err = d.UpdateAuthUserAccess(u.ID, "approved", "user")
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "approved" {
		t.Fatal("not approved")
	}
	u, err = d.UpdateAuthUserAccess(u.ID, "disabled", "user")
	if err != nil {
		t.Fatal(err)
	}
	if u.Status != "disabled" {
		t.Fatal("not disabled")
	}
}
