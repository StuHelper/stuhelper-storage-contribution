package contribution_test

import (
	"encoding/json"
	"errors"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"strings"
	"testing"
	"time"
)

func TestOwnedOptionsAndAdministratorRetryPreserveConsent(t *testing.T) {
	h := newFixture(t)
	q := h.request(t, "one")
	options, e := h.s.Options(h.ctx, user, 25, "")
	must(t, e)
	if len(options.Items) != 1 || options.Items[0].ID != "one" {
		t.Fatal(options)
	}
	if _, e = h.s.Options(h.ctx, operator, 25, ""); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal("operator impersonated contributor", e)
	}
	v, e := h.s.Create(h.ctx, user, "create", q)
	must(t, e)
	h.bridge.fail = true
	options, e = h.s.Options(h.ctx, user, 25, "")
	must(t, e)
	if len(options.Items) != 0 {
		t.Fatal("pending binding still offered")
	}
	for range 3 {
		if e = h.s.RunOne(h.ctx, "worker"); !errors.Is(e, contribution.ErrUnavailable) {
			t.Fatal(e)
		}
		h.clock.Add(10 * time.Second)
	}
	if _, e = h.s.Operations(h.ctx, user, 25, ""); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal("self grant read global inventory", e)
	}
	list, e := h.s.Operations(h.ctx, operator, 25, "")
	must(t, e)
	if len(list.Items) != 1 || list.Items[0].State != "blocked" {
		t.Fatal(list)
	}
	raw, e := json.Marshal(list)
	must(t, e)
	for _, field := range []string{"instance_id", "issuer", "owner:", "credential"} {
		if strings.Contains(string(raw), field) {
			t.Fatal("private data", field)
		}
	}
	request := contribution.RetryRequest{Revision: v.Revision}
	if _, e = h.s.RetryOperation(h.ctx, user, v.ID, "retry", request); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal(e)
	}
	retry, e := h.s.RetryOperation(h.ctx, operator, v.ID, "retry", request)
	must(t, e)
	if retry.Conditions != v.Conditions || retry.Consent != v.Consent || retry.DesiredState != v.DesiredState || retry.Revision != v.Revision+1 {
		t.Fatal("administrator changed consent", retry)
	}
	replay, e := h.s.RetryOperation(h.ctx, operator, v.ID, "retry", request)
	must(t, e)
	if replay.Revision != retry.Revision {
		t.Fatal("duplicate retry")
	}
	h.policy.deny("contributions.operations.retry", true)
	if _, e = h.s.RetryOperation(h.ctx, operator, v.ID, "retry", request); !errors.Is(e, contribution.ErrDenied) {
		t.Fatal("removed grant replay", e)
	}
	h.bridge.fail = false
	h.run(t)
	options, e = h.s.Options(h.ctx, user, 25, "")
	must(t, e)
	if len(options.Items) != 0 {
		t.Fatal("already bound option returned", options)
	}
}
