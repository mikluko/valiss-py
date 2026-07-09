// Interop harness for the Python port: exercises the Go valiss library
// against Python-produced credentials and vice versa. Driven by
// tests/test_interop.py.
//
//	go run . mint    # mint keys, tokens, and creds bundles; JSON to stdout
//	go run . verify  # verify a credential read as JSON from stdin
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nkeys"

	"github.com/mikluko/valiss/pkg/creds"
	"github.com/mikluko/valiss/pkg/token"
)

type minted struct {
	OperatorPub  string `json:"operator_pub"`
	JTI          string `json:"jti"`
	AccountCreds string `json:"account_creds"`
	UserCreds    string `json:"user_creds"`
}

type credential struct {
	OperatorPub string `json:"operator_pub"`
	JTI         string `json:"jti"`
	Token       string `json:"token"`
	UserToken   string `json:"user_token"`
	Timestamp   string `json:"timestamp"`
	Signature   string `json:"signature"`
}

type verified struct {
	TenantID string   `json:"tenant_id"`
	UserID   string   `json:"user_id"`
	Scopes   []string `json:"scopes"`
}

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: interop mint|verify")
	}
	switch os.Args[1] {
	case "mint":
		mint()
	case "verify":
		verify()
	default:
		log.Fatalf("unknown command %q", os.Args[1])
	}
}

func mint() {
	operator, err := nkeys.CreateOperator()
	check(err)
	operatorPub, err := operator.PublicKey()
	check(err)
	account, err := nkeys.CreateAccount()
	check(err)
	accountPub, err := account.PublicKey()
	check(err)
	accountSeed, err := account.Seed()
	check(err)
	user, err := nkeys.CreateUser()
	check(err)
	userPub, err := user.PublicKey()
	check(err)
	userSeed, err := user.Seed()
	check(err)

	tok, err := token.Issue(operator, "acme", accountPub, []string{"call:/v1/*"}, time.Hour)
	check(err)
	claims, err := token.Verify(tok, operatorPub)
	check(err)
	userTok, err := token.IssueUser(account, "alice", userPub, []string{"call:/v1/whoami"}, time.Hour)
	check(err)

	out := minted{
		OperatorPub:  operatorPub,
		JTI:          claims.ID,
		AccountCreds: creds.Format(creds.Bundle{Token: tok, Seed: accountSeed}),
		UserCreds:    creds.Format(creds.Bundle{Token: tok, UserToken: userTok, Seed: userSeed}),
	}
	check(json.NewEncoder(os.Stdout).Encode(out))
}

func verify() {
	var in credential
	check(json.NewDecoder(os.Stdin).Decode(&in))

	verifier := token.NewVerifier(in.OperatorPub, token.NewStaticAllowlist(in.JTI))
	claims, err := verifier.VerifyCredential(token.Credential{
		Token:     in.Token,
		UserToken: in.UserToken,
		Timestamp: in.Timestamp,
		Signature: in.Signature,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	check(json.NewEncoder(os.Stdout).Encode(verified{
		TenantID: claims.TenantID,
		UserID:   claims.UserID,
		Scopes:   claims.Scopes,
	}))
}

func check(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
