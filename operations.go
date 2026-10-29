package contribution

import (
	"context"
	storage "github.com/StuHelper/stuhelper-storage"
	"slices"
)

// Options derives ownership from the verified principal, never a query field.
func (s *Service) Options(ctx context.Context, p Principal, n int, after string) (storage.ContributionCandidates, error) {
	out := storage.ContributionCandidates{Items: []storage.ContributionCandidate{}}
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
		return out, e
	}
	page, e := s.store.ListContributionCandidates(ctx, s.cfg.Actor, OwnerDomain(p), n, after)
	if e != nil {
		return out, storeError(e)
	}
	bound := map[string]bool{}
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		records, e := tx.List(p, s.cfg.Policy.MaxPerOwner+1, "")
		if e != nil {
			return e
		}
		for _, r := range records {
			bound[r.InstanceID] = true
		}
		return nil
	})
	if e != nil {
		return out, e
	}
	for _, i := range page.Items {
		if !bound[i.ID] && slices.Contains(s.cfg.Policy.Adapters, i.Adapter) {
			out.Items = append(out.Items, i)
		}
	}
	out.NextCursor = page.NextCursor
	if e = s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
		return storage.ContributionCandidates{}, e
	}
	return out, nil
}
func (s *Service) Operations(ctx context.Context, p Principal, n int, after string) (Page, error) {
	out := Page{Items: []View{}}
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := s.authorize(ctx, p, "contributions.operations.read", Record{}); e != nil {
			return e
		}
		rs, e := tx.Scan(n+1, after)
		if e != nil {
			return e
		}
		if len(rs) > n {
			rs = rs[:n]
			out.NextCursor = rs[n-1].View.ID
		}
		for _, r := range rs {
			if e = s.authorize(ctx, p, "contributions.operations.read", r); e != nil {
				return e
			}
			out.Items = append(out.Items, s.view(r))
		}
		return s.authorize(ctx, p, "contributions.operations.read", Record{})
	})
	return out, e
}

type RetryRequest struct {
	Revision int64 `json:"revision"`
}

func (s *Service) RetryOperation(ctx context.Context, p Principal, id, key string, q RetryRequest) (View, error) {
	if q.Revision < 1 || id == "" {
		return View{}, ErrInput
	}
	return s.mutation(ctx, p, "contributions.operations.retry", id, key, q, func(_ Transaction, r *Record) error {
		v := &r.View
		if v.Revision != q.Revision || v.State != "blocked" {
			return ErrConflict
		}
		v.Revision++
		v.State = "pending"
		v.Reason = ""
		return nil
	})
}
