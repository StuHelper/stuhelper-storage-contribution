package contribution_test

import (
	"context"
	"errors"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"testing"
)

type operationsPolicy struct {
	*fixture
	batchCalls int
	fail       bool
}

func (p *operationsPolicy) Authorize(ctx context.Context, actor contribution.Principal, action string, target contribution.Access) error {
	if action == "contributions.operations.read" {
		return contribution.ErrDenied
	}
	return p.policy.Authorize(ctx, actor, action, target)
}
func (p *operationsPolicy) AuthorizeOperationReads(ctx context.Context, actor contribution.Principal, targets []contribution.Access) ([]bool, error) {
	p.batchCalls++
	if p.db.Stats().InUse != 0 {
		return nil, errors.New("authorization held a contribution connection")
	}
	if p.fail || actor != operator {
		return nil, contribution.ErrDenied
	}
	allowed := make([]bool, len(targets))
	for i, target := range targets {
		allowed[i] = target.Owner.Issuer == actor.Issuer
	}
	return allowed, nil
}

func TestOperationsPagesWithinCurrentSchoolScope(t *testing.T) {
	h := newFixture(t)
	for _, row := range []struct{ id, school string }{{"a", "urn:other"}, {"b", operator.Issuer}, {"c", "urn:other"}, {"d", operator.Issuer}} {
		must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
			return tx.SaveRecord(contribution.Record{InstanceID: row.id, Owner: contribution.Principal{Issuer: row.school, Subject: "student"}, View: contribution.View{ID: row.id}})
		}))
	}
	p := &operationsPolicy{fixture: h}
	s, e := contribution.New(h.repo, p, h.bridge, h.cfg)
	must(t, e)
	page, e := s.Operations(h.ctx, operator, 1, "")
	must(t, e)
	if len(page.Items) != 1 || page.Items[0].ID != "b" || page.NextCursor != "b" {
		t.Fatal(page)
	}
	next, e := s.Operations(h.ctx, operator, 1, page.NextCursor)
	must(t, e)
	if len(next.Items) != 1 || next.Items[0].ID != "d" || next.NextCursor != "" || p.batchCalls != 4 {
		t.Fatal(next, p.batchCalls)
	}
	p.fail = true
	hidden, e := s.Operations(h.ctx, operator, 100, "")
	if !errors.Is(e, contribution.ErrDenied) || len(hidden.Items) != 0 {
		t.Fatal(hidden, e)
	}
}

type legacyReadPolicy struct {
	*fixture
	gates  int
	revoke bool
}

func (l *legacyReadPolicy) Authorize(ctx context.Context, p contribution.Principal, action string, target contribution.Access) error {
	if action != "contributions.operations.read" {
		return l.policy.Authorize(ctx, p, action, target)
	}
	if l.db.Stats().InUse > 0 {
		return errors.New("authorization inside transaction")
	}
	if target.ID == "" {
		l.gates++
		if l.revoke && l.gates == 2 {
			return contribution.ErrDenied
		}
	} else if target.Owner.Issuer != p.Issuer {
		return contribution.ErrDenied
	}
	return l.policy.Authorize(ctx, p, action, target)
}
func TestLegacyOperationsAuthorizationRechecksBeforeReturn(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
		return tx.SaveRecord(contribution.Record{InstanceID: "other", Owner: contribution.Principal{Issuer: "other", Subject: "student"}, View: contribution.View{ID: "000"}})
	}))
	policy := &legacyReadPolicy{fixture: h}
	s, e := contribution.New(h.repo, policy, h.bridge, h.cfg)
	must(t, e)
	page, e := s.Operations(h.ctx, operator, 1, "")
	must(t, e)
	if len(page.Items) != 1 || page.Items[0].ID != v.ID || page.NextCursor != "" {
		t.Fatal(page)
	}
	policy.gates = 0
	policy.revoke = true
	page, e = s.Operations(h.ctx, operator, 1, "")
	if !errors.Is(e, contribution.ErrDenied) || len(page.Items) != 0 {
		t.Fatal(page, e)
	}
}
