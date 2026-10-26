// Package contribution manages voluntary storage consent without holding provider credentials.
package contribution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"regexp"
	"time"
)

var (
	ErrInput       = errors.New("contribution_invalid_input")
	ErrDenied      = errors.New("contribution_permission_denied")
	ErrNotFound    = errors.New("contribution_not_found")
	ErrConflict    = errors.New("contribution_conflict")
	ErrUnavailable = errors.New("contribution_unavailable")
)
var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Principal = storage.Principal
type Access struct {
	ID    string
	Owner Principal
}
type Authorizer interface {
	Authorize(context.Context, Principal, string, Access) error
}

// Store exposes only the provider-independent contribution control boundary.
type Store interface {
	InspectContribution(context.Context, Principal, string, string) (storage.ContributionSnapshot, error)
	ApplyContribution(context.Context, Principal, string, storage.ContributionControl) (storage.ContributionSnapshot, error)
}
type Terms struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
	URL     string `json:"url"`
}
type Consent struct {
	Accepted bool   `json:"accepted"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}
type Conditions struct {
	LimitBytes      int64     `json:"limit_bytes"`
	PersonalReserve int64     `json:"personal_reserve"`
	Until           time.Time `json:"until"`
}
type Policy struct {
	Terms                    Terms    `json:"terms"`
	Adapters                 []string `json:"adapters"`
	MinBytes                 int64    `json:"min_bytes"`
	MaxBytes                 int64    `json:"max_bytes"`
	MinTermSeconds           int64    `json:"min_term_seconds"`
	MaxTermSeconds           int64    `json:"max_term_seconds"`
	ExitTargetSeconds        int64    `json:"exit_target_seconds"`
	MaxPerOwner              int      `json:"max_per_owner"`
	ObservationMaxAgeSeconds int64    `json:"observation_max_age_seconds"`
}
type Config struct {
	Policy           Policy
	Actor            Principal
	Clock            func() time.Time
	OperationTimeout time.Duration
	RefreshInterval  time.Duration
	Lease            time.Duration
	MaxAttempts      int
	MaxContributions int
}
type CreateRequest struct {
	InstanceID string     `json:"instance_id"`
	Conditions Conditions `json:"conditions"`
	Consent    Consent    `json:"consent"`
}
type CommandRequest struct {
	Revision   int64       `json:"revision"`
	Action     string      `json:"action"`
	Conditions *Conditions `json:"conditions,omitempty"`
	Consent    *Consent    `json:"consent,omitempty"`
}
type Observation struct {
	ObservedAt             time.Time `json:"observed_at"`
	AuthorizationExpiresAt time.Time `json:"authorization_expires_at"`
	QuotaExpiresAt         time.Time `json:"quota_expires_at"`
	Authorized             bool      `json:"authorized"`
	UsedBytes              int64     `json:"used_bytes"`
	ReservedBytes          int64     `json:"reserved_bytes"`
	AvailableBytes         int64     `json:"available_bytes"`
	RemainingReplicas      int64     `json:"remaining_replicas"`
}

// View deliberately omits the principal, provider instance and all custody details.
type View struct {
	ID              string       `json:"id"`
	Adapter         string       `json:"adapter"`
	Revision        int64        `json:"revision"`
	AppliedRevision int64        `json:"applied_revision"`
	DesiredState    string       `json:"desired_state"`
	State           string       `json:"state"`
	Reason          string       `json:"reason"`
	Conditions      Conditions   `json:"conditions"`
	Consent         Terms        `json:"consent"`
	AcceptedAt      time.Time    `json:"accepted_at"`
	CreatedAt       time.Time    `json:"created_at"`
	UpdatedAt       time.Time    `json:"updated_at"`
	ExitRequestedAt *time.Time   `json:"exit_requested_at,omitempty"`
	ExitTargetAt    *time.Time   `json:"exit_target_at,omitempty"`
	Observation     *Observation `json:"observation,omitempty"`
}
type Page struct {
	Items      []View `json:"items"`
	NextCursor string `json:"next_cursor"`
}
type Statistics struct {
	DeclaredBytes     int64     `json:"declared_bytes"`
	AvailableBytes    int64     `json:"available_bytes"`
	UsedBytes         int64     `json:"used_bytes"`
	ReservedBytes     int64     `json:"reserved_bytes"`
	Contributions     int       `json:"contributions"`
	FreshObservations int       `json:"fresh_observations"`
	Status            string    `json:"status"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// Record and Job belong to this module's repository; they are never HTTP responses.
type Record struct {
	View          View
	Owner         Principal
	InstanceID    string
	EventRevision int64
}
type Job struct {
	ID          string
	State       string
	Generation  int64
	LeaseOwner  string
	LeaseUntil  time.Time
	AvailableAt time.Time
	Attempts    int
}
type Replay struct {
	Key, Hash string
	Result    View
	ExpiresAt time.Time
}
type Event struct {
	SpecVersion     string    `json:"specversion"`
	Source          string    `json:"source"`
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	Subject         string    `json:"subject"`
	Time            time.Time `json:"time"`
	DataContentType string    `json:"datacontenttype"`
	Data            EventData `json:"data"`
	Actor           Principal `json:"-"`
}
type EventData struct {
	Revision        int64  `json:"revision"`
	DesiredRevision int64  `json:"desired_revision"`
	AppliedRevision int64  `json:"applied_revision"`
	State           string `json:"state"`
}
type Repository interface {
	Transaction(context.Context, func(Transaction) error) error
	Claim(context.Context, string, time.Time, time.Duration) (Job, error)
	PendingEvents(context.Context, int) ([]Event, error)
	AcknowledgeEvent(context.Context, string) error
}

// Lock order is replay -> record -> job. Claim only locks a job, commits,
// then starts external work; a storage request never holds a module transaction.
type Transaction interface {
	Lock(string) error
	Record(string) (Record, error)
	SaveRecord(Record) error
	List(Principal, int, string) ([]Record, error)
	Scan(int, string) ([]Record, error)
	Counts(Principal) (total, owned int, err error)
	Job(string) (Job, error)
	SaveJob(Job) error
	Replay(string) (Replay, error)
	SaveReplay(Replay) error
	PruneReplays(time.Time, int) error
	Event(Event) error
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// OwnerDomain is the stable storage ownership binding, including identity issuer.
func OwnerDomain(p Principal) string { return "owner:" + hash(p) }
