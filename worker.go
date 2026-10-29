package contribution

import (
	"context"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"time"
)

func storeError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, storage.ErrDenied):
		return ErrDenied
	case errors.Is(e, storage.ErrNotFound):
		return ErrNotFound
	case errors.Is(e, storage.ErrConflict), errors.Is(e, storage.ErrStale), errors.Is(e, storage.ErrCapacity):
		return ErrConflict
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	default:
		return ErrUnavailable
	}
}

// Sweep converts expired consent into a durable exit request, including blocked
// activation jobs. Storage independently stops writes at the consent deadline.
func (s *Service) Sweep(ctx context.Context, n int, after string) (string, error) {
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return "", ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
		return "", e
	}
	var next string
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		rs, e := tx.Scan(n, after)
		if e != nil {
			return e
		}
		if len(rs) == n {
			next = rs[len(rs)-1].View.ID
		}
		for _, item := range rs {
			r, e := tx.Record(item.View.ID)
			if e != nil {
				return e
			}
			v := &r.View
			if (v.DesiredState == "active" || v.DesiredState == "paused") && !v.Conditions.Until.After(s.now()) {
				s.exit(v)
				v.Revision++
				v.State = "pending"
				v.Reason = "consent_expired"
				if e = s.emit(tx, s.cfg.Actor, "contribution.expired", &r); e != nil {
					return e
				}
				if e = s.enqueue(tx, r); e != nil {
					return e
				}
			}
		}
		if e = s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
			return e
		}
		return tx.PruneReplays(s.now(), 100)
	})
	return next, e
}
func (s *Service) RunOne(ctx context.Context, worker string) error {
	if !identifier.MatchString(worker) {
		return ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
		return e
	}
	j, e := s.repo.Claim(ctx, worker, s.now(), s.cfg.Lease)
	if e != nil {
		return e
	}
	var r Record
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		r, e = tx.Record(j.ID)
		if e != nil {
			return e
		}
		current, e := tx.Job(j.ID)
		if e != nil {
			return e
		}
		if current.Generation != j.Generation || current.State != "running" {
			return ErrConflict
		}
		return nil
	})
	if e != nil {
		return e
	}
	var snapshot storage.ContributionSnapshot
	operationErr := ErrUnavailable
	if j.Attempts <= s.cfg.MaxAttempts {
		snapshot, operationErr = s.synchronize(ctx, r)
	}
	// A canceled attempt leaves its lease for another process; no unbounded
	// detached write or retry is started during shutdown.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		current, e := tx.Record(j.ID)
		if e != nil {
			return e
		}
		job, e := tx.Job(j.ID)
		if e != nil {
			return e
		}
		if job.Generation != j.Generation || job.LeaseOwner != worker || job.State != "running" || !job.LeaseUntil.After(s.now()) || current.View.Revision != r.View.Revision {
			return ErrConflict
		}
		if e = s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
			return e
		}
		before := hash(current.View)
		v := &current.View
		if operationErr != nil {
			job.Attempts = j.Attempts
			v.Reason = "storage_unavailable"
			switch {
			case errors.Is(operationErr, ErrDenied):
				v.Reason = "authorization_required"
			case errors.Is(operationErr, ErrConflict):
				v.Reason = "storage_conflict"
			case errors.Is(operationErr, ErrNotFound):
				v.Reason = "binding_unavailable"
			}
			v.State = "blocked"
			job.State = "pending"
			job.AvailableAt = s.now().Add(time.Duration(1<<uint(job.Attempts)) * time.Second)
			if job.Attempts >= s.cfg.MaxAttempts || !errors.Is(operationErr, ErrUnavailable) {
				job.State = "blocked"
			}
		} else {
			v.AppliedRevision = v.Revision
			v.Observation = &Observation{snapshot.ObservedAt, snapshot.AuthorizationExpiresAt, snapshot.QuotaExpiresAt, snapshot.Authorized, snapshot.UsedBytes, snapshot.ReservedBytes, snapshot.AvailableBytes, snapshot.RemainingReplicas}
			v.Reason = ""
			v.State = v.DesiredState
			job.Attempts = 0
			job.State = "pending"
			job.AvailableAt = s.now().Add(s.cfg.RefreshInterval)
			switch {
			case v.DesiredState == "revoked":
				job.State = "complete"
				if snapshot.RemainingReplicas > 0 || snapshot.UsedBytes > 0 || snapshot.ReservedBytes > 0 {
					v.Reason = "cleanup_unconfirmed"
				}
			case v.DesiredState == "exiting" && snapshot.RemainingReplicas == 0 && snapshot.UsedBytes == 0 && snapshot.ReservedBytes == 0:
				v.State = "exited"
				job.State = "complete"
			case !snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now()):
				v.State = "blocked"
				v.Reason = "authorization_required"
			case snapshot.State != "active" && v.DesiredState == "active":
				v.State = "blocked"
				v.Reason = "storage_writes_disabled"
			case !snapshot.QuotaExpiresAt.After(s.now()):
				v.Reason = "capacity_unknown"
			}
			if v.DesiredState == "exiting" && v.State != "exited" && v.ExitTargetAt != nil && !v.ExitTargetAt.After(s.now()) && v.Reason == "" {
				v.Reason = "exit_overdue"
			}
		}
		job.LeaseUntil = time.Time{}
		job.LeaseOwner = ""
		if hash(current.View) != before {
			if e = s.emit(tx, s.cfg.Actor, "contribution.observed", &current); e != nil {
				return e
			}
		}
		return tx.SaveJob(job)
	})
	if e != nil {
		return e
	}
	return operationErr
}
func (s *Service) synchronize(ctx context.Context, r Record) (storage.ContributionSnapshot, error) {
	v := r.View
	snapshot, e := s.store.InspectContribution(ctx, s.cfg.Actor, r.InstanceID, OwnerDomain(r.Owner))
	if e != nil {
		return snapshot, storeError(e)
	}
	if snapshot.InstanceID != r.InstanceID || snapshot.Adapter != v.Adapter || snapshot.ObservedAt.After(s.now().Add(time.Second)) || snapshot.ObservedAt.Before(s.now().Add(-s.cfg.OperationTimeout)) {
		return snapshot, ErrUnavailable
	}
	state := v.DesiredState
	if state == "exiting" {
		state = "draining"
	}
	c := storage.ContributionControl{ID: v.ID, OwnerDomain: OwnerDomain(r.Owner), Revision: v.Revision, ExpectedRevision: snapshot.Revision, State: state, LimitBytes: v.Conditions.LimitBytes, PersonalReserve: v.Conditions.PersonalReserve, Until: v.Conditions.Until}
	// Reuse the permanent revision after a lost response. Storage compares all
	// consent fields; another owner or newer request cannot be overwritten.
	if e = s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
		return snapshot, e
	}
	snapshot, e = s.store.ApplyContribution(ctx, s.cfg.Actor, r.InstanceID, c)
	return snapshot, storeError(e)
}
