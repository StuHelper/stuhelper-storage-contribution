package contribution

import (
	"context"
	"errors"
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
	if !p.Valid() || p == s.cfg.Actor {
		return Page{}, ErrDenied
	}
	batch, grouped := s.auth.(OperationReadAuthorizer)
	const action = "contributions.operations.read"
	if grouped {
		_, err := batch.AuthorizeOperationReads(ctx, p, nil)
		if errors.Is(err, ErrDenied) {
			return Page{}, ErrDenied
		}
		if err != nil {
			return Page{}, ErrUnavailable
		}
	} else if err := s.authorize(ctx, p, action, Record{}); err != nil {
		return Page{}, err
	}
	// The registry admits at most 100 records. Scan once to fill a page across
	// hidden records and release the connection before checking permissions.
	var records []Record
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		records, err = tx.Scan(100, after)
		return err
	})
	if err != nil {
		return Page{}, err
	}
	var allowed []bool
	if grouped {
		targets := make([]Access, len(records))
		for i, r := range records {
			targets[i] = Access{ID: r.View.ID, Owner: r.Owner}
		}
		allowed, err = batch.AuthorizeOperationReads(ctx, p, targets)
		if errors.Is(err, ErrDenied) {
			return Page{}, ErrDenied
		}
		if err != nil || len(allowed) != len(records) {
			return Page{}, ErrUnavailable
		}
	}
	for i, r := range records {
		if grouped {
			if !allowed[i] {
				continue
			}
		} else if err := s.authorize(ctx, p, action, r); errors.Is(err, ErrDenied) {
			continue
		} else if err != nil {
			return Page{}, err
		}
		if len(out.Items) == n {
			out.NextCursor = out.Items[n-1].ID
			break
		}
		out.Items = append(out.Items, s.view(r))
	}
	if !grouped {
		if err := s.authorize(ctx, p, action, Record{}); err != nil {
			return Page{}, err
		}
	}
	return out, nil
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
