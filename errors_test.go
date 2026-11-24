package contribution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
	"github.com/StuHelper/stuhelper-storage/storagetest"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestStructuredErrorDetailCodesAndOccupiedFloor(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	cfg.Policy.MaxPerOwner = 1
	cfg.MaxContributions = 2
	svc, err := contribution.New(h.repo, h.policy, h.bridge, cfg)
	must(t, err)
	h.s = svc

	qOne := h.request(t, "one")
	qTwo := h.request(t, "two")
	otherUser := contribution.Principal{Issuer: "urn:fixture", Subject: "second-owner"}
	now := h.clock.Now()
	_, err = h.store.Register(h.ctx, system, "register-three", storage.Instance{
		ID: "three", Adapter: "fixture", AccountDomain: "fixture:three", OwnerDomain: contribution.OwnerDomain(otherUser),
		Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-three",
		State: "paused", Authorized: true, Limit: 0, ExpiresAt: now.Add(2 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(2 * time.Hour)}},
	})
	must(t, err)
	_, err = storagetest.RegisterContribution(h.ctx, h.store, system, "register-active", storage.Instance{
		ID: "already-active", Adapter: "fixture", AccountDomain: "fixture:active", OwnerDomain: contribution.OwnerDomain(user),
		Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-active",
		// This occupied account is ineligible for new contributions and cannot fit the later 16-byte object.
		State: "active", Authorized: true, Limit: 1, ExpiresAt: now.Add(2 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(2 * time.Hour)}},
	})
	must(t, err)

	handler, err := httpapi.New(h.s, multiUserAuth{})
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()

	clientFor := func(token string) *sdk.ClientWithResponses {
		c, err := sdk.NewClientWithResponses(srv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+token)
			return nil
		}))
		must(t, err)
		return c
	}
	client := clientFor("owner")

	toSDKCreate := func(q contribution.CreateRequest) sdk.CreateRequest {
		b, err := json.Marshal(q)
		must(t, err)
		var out sdk.CreateRequest
		must(t, json.Unmarshal(b, &out))
		return out
	}

	// 1. terms_version_mismatch (400)
	badTerms := qOne
	badTerms.Consent.Version = "outdated-v0"
	resp, err := client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "bad-terms"}, toSDKCreate(badTerms))
	must(t, err)
	if resp.StatusCode() != 400 || resp.JSON400 == nil || resp.JSON400.Code != "contribution_invalid_input" || resp.JSON400.DetailCode == nil || string(*resp.JSON400.DetailCode) != "terms_version_mismatch" {
		t.Fatalf("expected terms_version_mismatch, got %d %s", resp.StatusCode(), string(resp.Body))
	}

	// 2. limit_out_of_range (400)
	badLimit := qOne
	badLimit.Conditions.LimitBytes = cfg.Policy.MaxBytes + 1
	resp, err = client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "bad-limit"}, toSDKCreate(badLimit))
	must(t, err)
	if resp.StatusCode() != 400 || resp.JSON400 == nil || resp.JSON400.DetailCode == nil || string(*resp.JSON400.DetailCode) != "limit_out_of_range" {
		t.Fatalf("expected limit_out_of_range, got %d %s", resp.StatusCode(), string(resp.Body))
	}

	// 3. term_out_of_range (400)
	badTerm := qOne
	badTerm.Conditions.Until = now.Add(10 * time.Second)
	resp, err = client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "bad-term"}, toSDKCreate(badTerm))
	must(t, err)
	if resp.StatusCode() != 400 || resp.JSON400 == nil || resp.JSON400.DetailCode == nil || string(*resp.JSON400.DetailCode) != "term_out_of_range" {
		t.Fatalf("expected term_out_of_range, got %d %s", resp.StatusCode(), string(resp.Body))
	}

	// 4. instance_not_eligible (409 when instance is not paused)
	notPaused := qOne
	notPaused.InstanceID = "already-active"
	resp, err = client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "not-paused"}, toSDKCreate(notPaused))
	must(t, err)
	if resp.StatusCode() != 409 || resp.JSON409 == nil || resp.JSON409.Code != "contribution_conflict" || resp.JSON409.DetailCode == nil || string(*resp.JSON409.DetailCode) != "instance_not_eligible" {
		t.Fatalf("expected instance_not_eligible, got %d %s", resp.StatusCode(), string(resp.Body))
	}

	// Create valid contribution "one"
	created, err := client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "create-one"}, toSDKCreate(qOne))
	must(t, err)
	if created.JSON202 == nil {
		t.Fatalf("create failed: %d %s", created.StatusCode(), string(created.Body))
	}
	idOne := created.JSON202.Id

	// 5. idempotency_mismatch (409)
	changed := qOne
	changed.Conditions.LimitBytes = 512
	resp, err = client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "create-one"}, toSDKCreate(changed))
	must(t, err)
	if resp.StatusCode() != 409 || resp.JSON409 == nil || resp.JSON409.DetailCode == nil || string(*resp.JSON409.DetailCode) != "idempotency_mismatch" {
		t.Fatalf("expected idempotency_mismatch, got %d %s", resp.StatusCode(), string(resp.Body))
	}

	// 6. owner_quota_exceeded (409 when MaxPerOwner=1)
	resp, err = client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "create-two"}, toSDKCreate(qTwo))
	must(t, err)
	if resp.StatusCode() != 409 || resp.JSON409 == nil || resp.JSON409.DetailCode == nil || string(*resp.JSON409.DetailCode) != "owner_quota_exceeded" {
		t.Fatalf("expected owner_quota_exceeded, got %d %s", resp.StatusCode(), string(resp.Body))
	}

	// Activate "one" and ingest 16 bytes so UsedBytes = 16
	h.run(t)
	payload := strings.Repeat("k", 16)
	sum := sha256.Sum256([]byte(payload))
	obj, err := h.store.Create(h.ctx, system, "occupied-obj", storage.CreateRequest{
		Size: 16, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj.ID, "ingest-occupied", strings.NewReader(payload))
	must(t, err)
	// Refresh observation so Contribution records UsedBytes = 16
	paused, err := client.CommandContributionWithResponse(h.ctx, idOne, &sdk.CommandContributionParams{IdempotencyKey: "pause-1"}, sdk.CommandRequest{Revision: 1, Action: sdk.Pause})
	must(t, err)
	if paused.JSON202 == nil {
		t.Fatal(paused.StatusCode())
	}
	h.run(t)
	current := h.get(t, idOne)

	// 7. revision_conflict (409)
	revResp, err := client.CommandContributionWithResponse(h.ctx, idOne, &sdk.CommandContributionParams{IdempotencyKey: "bad-rev"}, sdk.CommandRequest{Revision: current.Revision + 5, Action: sdk.Resume})
	must(t, err)
	if revResp.StatusCode() != 409 || revResp.JSON409 == nil || revResp.JSON409.DetailCode == nil || string(*revResp.JSON409.DetailCode) != "revision_conflict" {
		t.Fatalf("expected revision_conflict, got %d %s", revResp.StatusCode(), string(revResp.Body))
	}

	// 8. invalid_state_transition (409: pause when already paused)
	stateResp, err := client.CommandContributionWithResponse(h.ctx, idOne, &sdk.CommandContributionParams{IdempotencyKey: "double-pause"}, sdk.CommandRequest{Revision: current.Revision, Action: sdk.Pause})
	must(t, err)
	if stateResp.StatusCode() != 409 || stateResp.JSON409 == nil || stateResp.JSON409.DetailCode == nil || string(*stateResp.JSON409.DetailCode) != "invalid_state_transition" {
		t.Fatalf("expected invalid_state_transition, got %d %s", stateResp.StatusCode(), string(stateResp.Body))
	}

	// 9. limit_below_occupied (409) with min_required_bytes == 16
	lowCond := sdk.Conditions{LimitBytes: 8, PersonalReserve: current.Conditions.PersonalReserve, Until: current.Conditions.Until}
	occResp, err := client.CommandContributionWithResponse(h.ctx, idOne, &sdk.CommandContributionParams{IdempotencyKey: "too-low"}, sdk.CommandRequest{Revision: current.Revision, Action: sdk.Configure, Conditions: &lowCond})
	must(t, err)
	if occResp.StatusCode() != 409 || occResp.JSON409 == nil || occResp.JSON409.DetailCode == nil || string(*occResp.JSON409.DetailCode) != "limit_below_occupied" || occResp.JSON409.MinRequiredBytes == nil || *occResp.JSON409.MinRequiredBytes != 16 {
		t.Fatalf("expected limit_below_occupied with min_required_bytes=16, got %d %s", occResp.StatusCode(), string(occResp.Body))
	}

	// 10. registry_full (409 when MaxContributions=2 is reached and third user tries to create)
	secondOwner := otherUser
	thirdOwner := contribution.Principal{Issuer: "urn:fixture", Subject: "third-owner"}
	_, err = h.store.Register(h.ctx, system, "register-four", storage.Instance{
		ID: "four", Adapter: "fixture", AccountDomain: "fixture:four", OwnerDomain: contribution.OwnerDomain(thirdOwner),
		Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-four",
		State: "paused", Authorized: true, Limit: 0, ExpiresAt: now.Add(2 * time.Hour),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now.Add(2 * time.Hour)}},
	})
	must(t, err)

	allowAllOwnersPolicy := &multiOwnerPolicy{}
	svcMulti, err := contribution.New(h.repo, allowAllOwnersPolicy, h.bridge, cfg)
	must(t, err)
	multiHandler, err := httpapi.New(svcMulti, multiUserAuth{})
	must(t, err)
	multiSrv := httptest.NewServer(multiHandler)
	defer multiSrv.Close()

	c2, err := sdk.NewClientWithResponses(multiSrv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+secondOwner.Subject)
		return nil
	}))
	must(t, err)
	qThree := qOne
	qThree.InstanceID = "three"
	r2, err := c2.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "c2"}, toSDKCreate(qThree))
	must(t, err)
	if r2.StatusCode() != 202 {
		t.Fatalf("expected 202 for second owner, got %d %s", r2.StatusCode(), string(r2.Body))
	}

	c3, err := sdk.NewClientWithResponses(multiSrv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+thirdOwner.Subject)
		return nil
	}))
	must(t, err)
	qFour := qOne
	qFour.InstanceID = "four"
	r3, err := c3.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "c3"}, toSDKCreate(qFour))
	must(t, err)
	if r3.StatusCode() != 409 || r3.JSON409 == nil || r3.JSON409.DetailCode == nil || string(*r3.JSON409.DetailCode) != "registry_full" {
		t.Fatalf("expected registry_full, got %d %s", r3.StatusCode(), string(r3.Body))
	}
}

type multiUserAuth struct{}

func (multiUserAuth) Authenticate(r *http.Request) (contribution.Principal, error) {
	hdr := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if hdr == "" || hdr == r.Header.Get("Authorization") {
		return contribution.Principal{}, contribution.ErrDenied
	}
	return contribution.Principal{Issuer: "urn:fixture", Subject: hdr}, nil
}

type multiOwnerPolicy struct{}

func (*multiOwnerPolicy) Authorize(_ context.Context, actor contribution.Principal, action string, a contribution.Access) error {
	if action == "contributions.maintenance" {
		if actor == system {
			return nil
		}
		return contribution.ErrDenied
	}
	if !actor.Valid() || actor != a.Owner {
		return contribution.ErrDenied
	}
	return nil
}
