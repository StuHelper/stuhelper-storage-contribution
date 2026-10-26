package contribution

import (
	"context"
	"errors"
	"net/url"
	"slices"
	"time"
)

type Service struct {
	repo  Repository
	auth  Authorizer
	store Store
	cfg   Config
}

func New(r Repository, a Authorizer, st Store, c Config) (*Service, error) {
	u, e := url.Parse(c.Policy.Terms.URL)
	p := c.Policy
	if r == nil || a == nil || st == nil || !c.Actor.Valid() || c.Clock == nil || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !identifier.MatchString(p.Terms.Version) || !digestPattern.MatchString(p.Terms.Digest) || len(p.Adapters) == 0 || len(p.Adapters) > 20 || p.MinBytes < 1 || p.MaxBytes < p.MinBytes || p.MaxBytes > 1<<46 || p.MinTermSeconds < 1 || p.MaxTermSeconds < p.MinTermSeconds || p.MaxTermSeconds > 366*86400 || p.ExitTargetSeconds < 1 || p.ExitTargetSeconds > 366*86400 || p.MaxPerOwner < 1 || p.MaxPerOwner > 100 || c.MaxContributions < p.MaxPerOwner || c.MaxContributions > 100 || c.MaxAttempts < 1 || c.MaxAttempts > 10 || c.OperationTimeout < time.Second || c.OperationTimeout > time.Minute || c.Lease < 2*c.OperationTimeout || c.Lease > 10*time.Minute || c.RefreshInterval < time.Second || c.RefreshInterval > time.Hour || p.ObservationMaxAgeSeconds < int64(c.RefreshInterval/time.Second) || p.ObservationMaxAgeSeconds > 3600 {
		return nil, ErrInput
	}
	for _, adapter := range p.Adapters {
		if !identifier.MatchString(adapter) {
			return nil, ErrInput
		}
	}
	c.Policy.Adapters = slices.Clone(p.Adapters)
	return &Service{r, a, st, c}, nil
}
func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }
func (s *Service) Policy() Policy { p := s.cfg.Policy; p.Adapters = slices.Clone(p.Adapters); return p }
func (s *Service) authorize(ctx context.Context, p Principal, action string, r Record) error {
	if !p.Valid() || (action != "contributions.maintenance" && (p == s.cfg.Actor || p != r.Owner)) {
		return ErrDenied
	}
	if e := s.auth.Authorize(ctx, p, action, Access{r.View.ID, r.Owner}); e != nil {
		if errors.Is(e, ErrDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	return nil
}
func (s *Service) validConditions(c Conditions) bool {
	now := s.now()
	p := s.cfg.Policy
	return c.LimitBytes >= p.MinBytes && c.LimitBytes <= p.MaxBytes && c.PersonalReserve >= 0 && c.PersonalReserve <= 1<<46 && !c.Until.Before(now.Add(time.Duration(p.MinTermSeconds)*time.Second)) && !c.Until.After(now.Add(time.Duration(p.MaxTermSeconds)*time.Second))
}
func (s *Service) validConsent(c Consent) bool {
	return c.Accepted && c.Version == s.cfg.Policy.Terms.Version && c.Digest == s.cfg.Policy.Terms.Digest
}
func (s *Service) emit(tx Transaction, p Principal, kind string, r *Record) error {
	r.EventRevision++
	r.View.UpdatedAt = s.now()
	e := Event{SpecVersion: "1.0", Source: "stuhelper://storage-contribution", ID: hash([]any{r.View.ID, r.EventRevision}), Type: kind, Subject: r.View.ID, Time: s.now(), DataContentType: "application/json", Data: EventData{r.EventRevision, r.View.Revision, r.View.AppliedRevision, r.View.State}, Actor: p}
	if err := tx.SaveRecord(*r); err != nil {
		return err
	}
	return tx.Event(e)
}
func (s *Service) enqueue(tx Transaction, r Record) error {
	j, e := tx.Job(r.View.ID)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	j.ID = r.View.ID
	j.Generation++
	j.State = "pending"
	j.Attempts = 0
	j.AvailableAt = s.now()
	j.LeaseUntil = time.Time{}
	j.LeaseOwner = ""
	return tx.SaveJob(j)
}
func (s *Service) mutation(ctx context.Context, p Principal, action, id, key string, request any, run func(Transaction, *Record) error) (View, error) {
	var out View
	if !identifier.MatchString(key) || (id != "" && !identifier.MatchString(id)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	replayKey := hash([]any{p, action, id, key})
	payload := hash(request)
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("replay:" + replayKey); e != nil {
			return e
		}
		r := Record{Owner: p}
		if id != "" {
			var e error
			r, e = tx.Record(id)
			if e != nil {
				return e
			}
		}
		if e := s.authorize(ctx, p, action, r); e != nil {
			return e
		}
		old, e := tx.Replay(replayKey)
		if e == nil && old.ExpiresAt.After(s.now()) {
			if old.Hash != payload {
				return ErrConflict
			}
			out = old.Result
			return nil
		}
		if e != nil && !errors.Is(e, ErrNotFound) {
			return e
		}
		if e = run(tx, &r); e != nil {
			return e
		}
		if e = s.authorize(ctx, p, action, r); e != nil {
			return e
		}
		if e = s.emit(tx, p, "contribution.requested", &r); e != nil {
			return e
		}
		if e = s.enqueue(tx, r); e != nil {
			return e
		}
		out = s.view(r)
		return tx.SaveReplay(Replay{replayKey, payload, out, s.now().Add(24 * time.Hour)})
	})
	return out, err
}
func (s *Service) Create(ctx context.Context, p Principal, key string, q CreateRequest) (View, error) {
	if !identifier.MatchString(q.InstanceID) {
		return View{}, ErrInput
	}
	// Read-only verification happens before the local transaction; the worker
	// repeats it and the storage revision precondition closes the race.
	if e := s.authorize(ctx, p, "contributions.create", Record{Owner: p}); e != nil {
		return View{}, e
	}
	lookup, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	snapshot, e := s.store.InspectContribution(lookup, s.cfg.Actor, q.InstanceID, OwnerDomain(p))
	if e != nil {
		return View{}, storeError(e)
	}
	if snapshot.InstanceID != q.InstanceID || !slices.Contains(s.cfg.Policy.Adapters, snapshot.Adapter) {
		return View{}, ErrInput
	}
	return s.mutation(ctx, p, "contributions.create", "", key, q, func(tx Transaction, r *Record) error {
		if !s.validConditions(q.Conditions) || !s.validConsent(q.Consent) {
			return ErrInput
		}
		if !snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now()) || snapshot.State != "paused" || snapshot.Control != nil || snapshot.UsedBytes != 0 || snapshot.ReservedBytes != 0 || snapshot.RemainingReplicas != 0 {
			return ErrConflict
		}
		if e := tx.Lock("registry"); e != nil {
			return e
		}
		total, owned, e := tx.Counts(p)
		if e != nil {
			return e
		}
		if total >= s.cfg.MaxContributions || owned >= s.cfg.Policy.MaxPerOwner {
			return ErrConflict
		}
		stableID := hash([]string{"contribution", q.InstanceID})
		if _, e = tx.Record(stableID); e == nil {
			return ErrConflict
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		r.InstanceID = q.InstanceID
		// One permanent binding per instance makes late replays safe beyond the
		// response retention window. Reuse needs a separately reviewed flow.
		r.View = View{ID: hash([]string{"contribution", q.InstanceID}), Adapter: snapshot.Adapter, Revision: 1, DesiredState: "active", State: "pending", Conditions: q.Conditions, Consent: s.cfg.Policy.Terms, AcceptedAt: s.now(), CreatedAt: s.now(), UpdatedAt: s.now()}
		return nil
	})
}
func (s *Service) Command(ctx context.Context, p Principal, id, key string, q CommandRequest) (View, error) {
	if q.Revision < 1 {
		return View{}, ErrInput
	}
	return s.mutation(ctx, p, "contributions.manage", id, key, q, func(_ Transaction, r *Record) error {
		v := &r.View
		if v.Revision != q.Revision || v.State == "exited" {
			return ErrConflict
		}
		if q.Action != "configure" && q.Action != "renew" && (q.Conditions != nil || q.Consent != nil) {
			return ErrInput
		}
		switch q.Action {
		case "pause":
			if v.DesiredState != "active" {
				return ErrConflict
			}
			v.DesiredState = "paused"
		case "resume":
			if v.DesiredState != "paused" || !v.Conditions.Until.After(s.now()) {
				return ErrConflict
			}
			v.DesiredState = "active"
		case "exit":
			if v.DesiredState != "active" && v.DesiredState != "paused" {
				return ErrConflict
			}
			s.exit(v)
		case "revoke":
			if v.DesiredState == "revoked" {
				return ErrConflict
			}
			v.DesiredState = "revoked"
		case "retry":
			if v.State != "blocked" {
				return ErrConflict
			}
		case "configure", "renew":
			if v.DesiredState != "active" && v.DesiredState != "paused" {
				return ErrConflict
			}
			if q.Conditions == nil || q.Conditions.LimitBytes < s.cfg.Policy.MinBytes || q.Conditions.LimitBytes > s.cfg.Policy.MaxBytes || q.Conditions.PersonalReserve < 0 || q.Conditions.PersonalReserve > 1<<46 {
				return ErrInput
			}
			if v.Observation != nil && q.Conditions.LimitBytes < v.Observation.UsedBytes+v.Observation.ReservedBytes {
				return ErrConflict
			}
			if q.Action == "configure" {
				if q.Consent != nil || !q.Conditions.Until.Equal(v.Conditions.Until) || !v.Conditions.Until.After(s.now()) {
					return ErrInput
				}
			} else {
				if q.Consent == nil || !s.validConsent(*q.Consent) || !s.validConditions(*q.Conditions) || !q.Conditions.Until.After(v.Conditions.Until) {
					return ErrInput
				}
				v.Consent = s.cfg.Policy.Terms
				v.AcceptedAt = s.now()
			}
			v.Conditions = *q.Conditions
		default:
			return ErrInput
		}
		v.Revision++
		v.State = "pending"
		v.Reason = ""
		return nil
	})
}
func (s *Service) exit(v *View) {
	v.DesiredState = "exiting"
	now := s.now()
	target := now.Add(time.Duration(s.cfg.Policy.ExitTargetSeconds) * time.Second)
	v.ExitRequestedAt = &now
	v.ExitTargetAt = &target
}
func (s *Service) fresh(v View) bool {
	o := v.Observation
	now := s.now()
	return o != nil && !o.ObservedAt.After(now) && o.ObservedAt.After(now.Add(-time.Duration(s.cfg.Policy.ObservationMaxAgeSeconds)*time.Second)) && o.Authorized && o.AuthorizationExpiresAt.After(now) && o.QuotaExpiresAt.After(now)
}
func (s *Service) view(r Record) View {
	v := r.View
	if v.Observation != nil {
		o := *v.Observation
		v.Observation = &o
		if !s.fresh(v) || v.State != "active" || v.DesiredState != "active" || !v.Conditions.Until.After(s.now()) {
			o.AvailableBytes = 0
		}
	}
	if v.State == "active" && !s.fresh(v) {
		v.Reason = "observation_stale"
	}
	if (v.DesiredState == "active" || v.DesiredState == "paused") && !v.Conditions.Until.After(s.now()) {
		v.Reason = "consent_expired"
	}
	return v
}
func (s *Service) Get(ctx context.Context, p Principal, id string) (View, error) {
	var out View
	if !identifier.MatchString(id) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		r, e := tx.Record(id)
		if e != nil {
			return e
		}
		if e = s.authorize(ctx, p, "contributions.read", r); e != nil {
			return e
		}
		out = s.view(r)
		return nil
	})
	return out, e
}
func (s *Service) List(ctx context.Context, p Principal, n int, after string) (Page, error) {
	out := Page{Items: []View{}}
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
			return e
		}
		rs, e := tx.List(p, n+1, after)
		if e != nil {
			return e
		}
		if len(rs) > n {
			rs = rs[:n]
			out.NextCursor = rs[n-1].View.ID
		}
		for _, r := range rs {
			out.Items = append(out.Items, s.view(r))
		}
		return s.authorize(ctx, p, "contributions.read", Record{Owner: p})
	})
	return out, e
}
func (s *Service) Statistics(ctx context.Context) (Statistics, error) {
	out := Statistics{Status: "current", GeneratedAt: s.now()}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		rs, e := tx.Scan(s.cfg.MaxContributions+1, "")
		if e != nil {
			return e
		}
		if len(rs) > s.cfg.MaxContributions {
			return ErrUnavailable
		}
		for _, r := range rs {
			v := s.view(r)
			if v.State == "exited" {
				continue
			}
			out.Contributions++
			if v.DesiredState == "active" || v.DesiredState == "paused" {
				out.DeclaredBytes += v.Conditions.LimitBytes
			}
			if s.fresh(v) {
				out.FreshObservations++
			}
			if v.Observation != nil {
				out.UsedBytes += v.Observation.UsedBytes
				out.ReservedBytes += v.Observation.ReservedBytes
				out.AvailableBytes += v.Observation.AvailableBytes
			}
		}
		if out.FreshObservations != out.Contributions {
			out.Status = "partial"
		}
		return nil
	})
	return out, e
}
