package contribution

import (
	"context"
	"errors"
	"slices"

	storage "github.com/StuHelper/stuhelper-storage"
)

type AdoptionRequest struct {
	Owner             Principal
	InstanceID        string
	Adapter           string
	InstanceRevision  int64
	ApprovalReference string
	Conditions        Conditions
	Consent           Consent
}

type adoptionStore interface {
	AdoptContribution(context.Context, storage.Principal, string, storage.ContributionAdoption) (storage.ContributionSnapshot, error)
}

// RequestAdoption records an owner's separately documented approval for a
// previously verified instance. The existing job processor completes the move.
func (s *Service) RequestAdoption(ctx context.Context, actor Principal, key string, in AdoptionRequest) (View, error) {
	if actor != s.cfg.Actor {
		return View{}, ErrDenied
	}
	if !in.Owner.Valid() || !identifier.MatchString(in.InstanceID) || !identifier.MatchString(in.ApprovalReference) ||
		in.InstanceRevision < 1 || !slices.Contains(s.cfg.Policy.Adapters, in.Adapter) {
		return View{}, ErrInput
	}
	if _, ok := s.store.(adoptionStore); !ok {
		return View{}, ErrUnavailable
	}
	return s.mutationLocked(ctx, actor, "contributions.adopt", "", key, true, in, func(tx Transaction, r *Record) error {
		if !s.validConsent(in.Consent) {
			return detailErr(ErrInput, "terms_version_mismatch")
		}
		// An adoption preserves the verified quota of this instance. Storage
		// independently matches these conditions against the existing ledger.
		if in.Conditions.LimitBytes > 1<<60 || !s.validConditionsWithLimit(in.Conditions, in.Conditions.LimitBytes) {
			return detailErr(ErrInput, "invalid_approved_conditions")
		}
		stableID := hash([]string{"contribution", in.InstanceID})
		if _, err := tx.Record(stableID); err == nil {
			return detailErr(ErrConflict, "already_bound")
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		activations, err := s.checkAdmissionBudget(tx, in.Owner, nil)
		if err != nil {
			return err
		}
		now := s.now()
		r.Owner = in.Owner
		r.InstanceID = in.InstanceID
		r.Activations = activations
		r.Adoption = &in
		r.View = View{
			ID: stableID, Adapter: in.Adapter, Revision: 1, DesiredState: "active", State: "pending",
			Conditions: in.Conditions, Consent: s.cfg.Policy.Terms,
			AcceptedAt: now, CreatedAt: now, UpdatedAt: now,
		}
		return nil
	})
}

func (s *Service) applyAdoption(ctx context.Context, r Record) error {
	store, ok := s.store.(adoptionStore)
	if !ok {
		return ErrUnavailable
	}
	in := r.Adoption
	_, err := store.AdoptContribution(ctx, s.cfg.Actor, "contribution-adopt:"+r.View.ID, storage.ContributionAdoption{
		Owner: r.Owner, InstanceID: r.InstanceID, ApprovalReference: in.ApprovalReference,
		Control: storage.ContributionControl{
			ID: r.View.ID, OwnerDomain: OwnerDomain(r.Owner), Revision: 1,
			ExpectedRevision: in.InstanceRevision, State: "active",
			LimitBytes: in.Conditions.LimitBytes, PersonalReserve: in.Conditions.PersonalReserve, Until: in.Conditions.Until,
		},
	})
	return storeError(err)
}
