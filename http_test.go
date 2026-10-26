package contribution_test

import (
	"context"
	"encoding/json"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fixtureAuth struct{}

func (fixtureAuth) Authenticate(r *http.Request) (contribution.Principal, error) {
	if r.Header.Get("Authorization") != "Bearer fixture" {
		return contribution.Principal{}, contribution.ErrDenied
	}
	return user, nil
}
func TestHTTPGeneratedSDKAndPrivateDataBoundary(t *testing.T) {
	h := newFixture(t)
	handler, e := httpapi.New(h.s, fixtureAuth{})
	must(t, e)
	server := httptest.NewServer(handler)
	defer server.Close()
	anonymous, e := sdk.NewClientWithResponses(server.URL)
	must(t, e)
	p, e := anonymous.GetContributionPolicyWithResponse(h.ctx)
	must(t, e)
	if p.JSON200 == nil || p.JSON200.Terms.Version != h.cfg.Policy.Terms.Version {
		t.Fatal(p)
	}
	page, e := anonymous.ListContributionsWithResponse(h.ctx, nil)
	must(t, e)
	if page.StatusCode() != 401 {
		t.Fatal(page.StatusCode())
	}
	client, e := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture")
		return nil
	}))
	must(t, e)
	q := h.request(t, "one")
	b, e := json.Marshal(q)
	must(t, e)
	var input sdk.CreateRequest
	must(t, json.Unmarshal(b, &input))
	created, e := client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "create"}, input)
	must(t, e)
	if created.JSON202 == nil || string(created.JSON202.State) != "pending" {
		t.Fatal(created.StatusCode(), string(created.Body))
	}
	for _, forbidden := range []string{"instance_id", "issuer", "credential", "fixture:one", "owner:"} {
		if strings.Contains(string(created.Body), forbidden) {
			t.Fatal("private data in response", forbidden)
		}
	}
	bad, e := client.CreateContributionWithBodyWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "bad"}, "application/json", strings.NewReader(`{"instance_id":"one","owner":{"subject":"foreign"}}`))
	must(t, e)
	if bad.StatusCode() != 400 {
		t.Fatal(bad.StatusCode())
	}
	h.run(t)
	command, e := client.CommandContributionWithResponse(h.ctx, created.JSON202.Id, &sdk.CommandContributionParams{IdempotencyKey: "pause"}, sdk.CommandRequest{Revision: 1, Action: sdk.Pause})
	must(t, e)
	if command.JSON202 == nil || string(command.JSON202.DesiredState) != "paused" || string(command.JSON202.State) != "pending" {
		t.Fatal(command.StatusCode(), string(command.Body))
	}
	h.run(t)
	fetched, e := client.GetContributionWithResponse(h.ctx, created.JSON202.Id)
	must(t, e)
	if fetched.JSON200 == nil || string(fetched.JSON200.State) != "paused" {
		t.Fatal(fetched)
	}
	stats, e := anonymous.GetContributionStatisticsWithResponse(h.ctx)
	must(t, e)
	if stats.JSON200 == nil || stats.JSON200.AvailableBytes != 0 {
		t.Fatal(stats)
	}
}
