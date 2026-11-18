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
	bound := map[string]bool{}
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		records, e := tx.List(p, registryLimit, "")
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
	// Storage can return short or empty pages with a continuation after its
	// own authorization-expiry filter. Continue until we have a visible lookahead.
	const batchSize = 100
	const maxBatches = 10
	for range maxBatches {
		page, err := s.store.ListContributionCandidates(ctx, s.cfg.Actor, OwnerDomain(p), batchSize, after)
		if err != nil {
			return storage.ContributionCandidates{}, storeError(err)
		}
		for _, item := range page.Items {
			if !bound[item.ID] && slices.Contains(s.cfg.Policy.Adapters, item.Adapter) {
				out.Items = append(out.Items, item)
				if len(out.Items) > n {
					break
				}
			}
		}
		if len(out.Items) > n {
			out.Items = out.Items[:n]
			out.NextCursor = out.Items[n-1].ID
			break
		}
		out.NextCursor = page.NextCursor
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor <= after || !identifier.MatchString(page.NextCursor) {
			return storage.ContributionCandidates{}, ErrUnavailable
		}
		after = page.NextCursor
	}
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
