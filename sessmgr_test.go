package session

import (
	"testing"
	"time"

	lbcf "github.com/lidstromberg/config"
	kp "github.com/lidstromberg/keypair"

	context "golang.org/x/net/context"
)

func createNewSess(ctx context.Context) (*SessMgr, error) {
	bc := lbcf.NewConfig(ctx)

	//create a keypair
	kpr, err := kp.NewKeyPair(ctx, bc)

	if err != nil {
		return nil, err
	}

	sm1, err := NewSessMgr(ctx, bc, kpr)

	if err != nil {
		return nil, err
	}

	return sm1, nil
}

func Test_NewSessMgr(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	if sm1 == nil {
		t.Fatal("session manager failed to create")
	}
}
func Test_NewSession(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	t.Logf("Session string (jwt): %s", sess)
}
func Test_CheckUserRole(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	result, err := sm1.CheckUserRole(ctx, sess, "testapp1")

	if err != nil {
		t.Fatal(err)
	}

	if !result {
		t.Fatal("Failed to identify testapp1")
	}

	result, err = sm1.CheckUserRole(ctx, sess, "testapp3")

	if err != nil {
		t.Fatal(err)
	}

	if result {
		t.Fatal("Failed to reject testapp3")
	}
}
func Test_IsValid(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	t.Logf("Session string (jwt): %s", sess)

	chk, err := sm1.IsSessionValid(ctx, sess)

	if err != nil {
		t.Fatal(err)
	}

	if !chk {
		t.Fatal("session string (jwt) should be valid")
	}
}
func Test_GetSessionHeader(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	t.Logf("Session string (jwt): %s", sess)

	shdr1, err := sm1.GetJwtClaim(ctx, sess)

	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Session header useraccount: %s", shdr1["aid"].(string))
	t.Logf("Session header sessionid: %s", shdr1["jti"].(string))
	t.Logf("Session header roletoken: %s", shdr1["rle"].(string))
	t.Logf("Session header email: %s", shdr1["eml"].(string))
	t.Logf("Session header claims: %v", shdr1["clm"])
}
func Test_RefreshSession(t *testing.T) {
	//Note: this contains a 1 second wait to simulate elapsed user time between api calls
	//Remember to factor this in when benchmarking execution speeds
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	t.Logf("Session string (jwt): %s", sess)

	//this simulates time elapsed on the client side
	time.Sleep(1 * time.Second)

	//this would need to be declared
	var (
		newsess string
		newerr  error
	)

	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	resultch := sm1.RefreshSession(ctx, sess)
	t.Log("Doing stuff..")

	select {
	case r, ok := <-resultch:
		if ok == false {
			break
		}
		if _, ok := r.(error); ok {
			newerr = r.(error)
			break
		}
		if _, ok := r.(string); ok {
			newsess = r.(string)
			break
		}
	}

	if newerr != nil {
		t.Fatal(newerr)
	}

	t.Logf("New session string (jwt): %s", newsess)

	if newsess == sess {
		t.Fatal("refresh failed - identical session string (jwt) was generated")
	}
}
func Test_SetAppClaim(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	sess, err = sm1.SetAppClaim(ctx, sess, "testapp1.editor", "ready-writey")

	if err != nil {
		t.Fatal(err)
	}

	//now see if the claim was set correctly in the jwt
	shdr1, err := sm1.GetJwtClaimElement(ctx, sess, "testapp1.editor")

	if err != nil {
		t.Fatal(err)
	}

	if shdr1 == nil {
		t.Fatal("New claim did not set correctly")
	}

	t.Logf("Found claim: %s", shdr1.(string))
}
func Test_DeleteAppClaim(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	sess, err = sm1.SetAppClaim(ctx, sess, "testapp1.editor", "ready-writey")

	if err != nil {
		t.Fatal(err)
	}

	//now see if the claim was set correctly in the jwt
	shdr1, err := sm1.GetJwtClaimElement(ctx, sess, "testapp1.editor")

	if err != nil {
		t.Fatal(err)
	}

	if shdr1 == nil {
		t.Fatal("New claim did not set correctly")
	}

	if shdr1.(string) != "ready-writey" {
		t.Fatal("New claim did not set correctly")
	}

	sess, err = sm1.DeleteAppClaim(ctx, sess, "testapp1.editor")

	if err != nil {
		t.Fatal(err)
	}

	shdr1, err = sm1.GetJwtClaimElement(ctx, sess, "testapp1.editor")

	if err != nil && err != ErrClaimElementNotExist {
		t.Fatal(err)
	}

	if shdr1 != nil {
		t.Fatal("New claim did not clear correctly")
	}
}

//broader logic tests
func Test_UpdateAppClaim(t *testing.T) {
	ctx := context.Background()

	sm1, err := createNewSess(ctx)

	if err != nil {
		t.Fatal(err)
	}

	sess, err := sm1.NewSession(ctx, "dummyUser1", "session@sessiontest.com", "testapp1:testapp2")

	if err != nil {
		t.Fatal(err)
	}

	if sess == "" {
		t.Fatal("session string (jwt) failed to create")
	}

	sess, err = sm1.SetAppClaim(ctx, sess, "testapp1.editor", "ready-writey")

	if err != nil {
		t.Fatal(err)
	}

	//now see if the claim was set correctly in the jwt
	shdr1, err := sm1.GetJwtClaimElement(ctx, sess, "testapp1.editor")

	if err != nil {
		t.Fatal(err)
	}

	if shdr1 == nil {
		t.Fatal("New claim did not set correctly")
	}

	var foundit bool
	if shdr1.(string) == "ready-writey" {
		foundit = true
	}

	if !foundit {
		t.Fatal("New claim did not set correctly")
	}

	//now update the claim
	sess, err = sm1.SetAppClaim(ctx, sess, "testapp1.editor", "ready")

	if err != nil {
		t.Fatal(err)
	}

	//now see if the claim was updated correctly in the jwt
	shdr1, err = sm1.GetJwtClaimElement(ctx, sess, "testapp1.editor")

	if err != nil {
		t.Fatal(err)
	}

	if shdr1 == nil {
		t.Fatal("Updated claim did not set correctly")
	}

	if shdr1.(string) == "ready" {
		t.Logf("Found claim: %s", shdr1.(string))
		return
	}

	t.Fatal("Updated claim did not set correctly")
}
