// Package httpapi exposes user-owned contribution requests and anonymous aggregate policy.
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"
)

type Authenticator interface {
	Authenticate(*http.Request) (contribution.Principal, error)
}
type endpoint func(*http.Request, contribution.Principal) (any, error)

func New(s *contribution.Service, a Authenticator) (http.Handler, error) {
	if s == nil || a == nil {
		return nil, contribution.ErrInput
	}
	m := http.NewServeMux()
	mount := func(pattern string, public bool, status int, run endpoint) {
		m.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
			defer cancel()
			r = r.WithContext(ctx)
			controller := http.NewResponseController(w)
			deadline, _ := ctx.Deadline()
			_ = controller.SetReadDeadline(deadline)
			_ = controller.SetWriteDeadline(deadline)
			r.Body = http.MaxBytesReader(w, r.Body, 16384)
			var p contribution.Principal
			if !public {
				var e error
				p, e = a.Authenticate(r)
				if e != nil || !p.Valid() {
					if errors.Is(e, contribution.ErrUnavailable) {
						failure(w, e)
					} else {
						problem(w, 401, "authentication_required")
					}
					return
				}
			}
			if len(r.Header.Values("Idempotency-Key")) > 1 {
				failure(w, contribution.ErrInput)
				return
			}
			out, e := run(r, p)
			if e != nil {
				failure(w, e)
				return
			}
			write(w, status, out)
		})
	}
	base := "/api/v1/storage-contributions"
	mount("GET "+base+"/options", false, 200, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r, "limit", "after"); e != nil {
			return nil, e
		}
		n, e := pageSize(r)
		if e != nil {
			return nil, e
		}
		return s.Options(r.Context(), p, n, r.URL.Query().Get("after"))
	})
	mount("GET "+base+"/operations", false, 200, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r, "limit", "after", "state", "reason", "adapter"); e != nil {
			return nil, e
		}
		n, e := pageSize(r)
		if e != nil {
			return nil, e
		}
		q := r.URL.Query()
		return s.OperationsFiltered(r.Context(), p, contribution.OperationsFilter{
			Limit:   n,
			After:   q.Get("after"),
			State:   q.Get("state"),
			Reason:  q.Get("reason"),
			Adapter: q.Get("adapter"),
		})
	})
	mount("GET "+base+"/operations/metrics", false, 200, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		return s.MetricsSnapshot(r.Context(), p)
	})
	mount("POST "+base+"/operations/{id}/retry", false, 202, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		var q contribution.RetryRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.RetryOperation(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), q)
	})
	mount("GET "+base+"/policy", true, 200, func(r *http.Request, _ contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		return s.Policy(), nil
	})
	mount("GET "+base+"/statistics", true, 200, func(r *http.Request, _ contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		return s.Statistics(r.Context())
	})
	mount("POST "+base, false, 202, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		var q contribution.CreateRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.Create(r.Context(), p, r.Header.Get("Idempotency-Key"), q)
	})
	mount("GET "+base, false, 200, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r, "limit", "after"); e != nil {
			return nil, e
		}
		n, e := pageSize(r)
		if e != nil {
			return nil, e
		}
		return s.List(r.Context(), p, n, r.URL.Query().Get("after"))
	})
	mount("GET "+base+"/{id}", false, 200, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		return s.Get(r.Context(), p, r.PathValue("id"))
	})
	mount("POST "+base+"/{id}/commands", false, 202, func(r *http.Request, p contribution.Principal) (any, error) {
		if e := checkQuery(r); e != nil {
			return nil, e
		}
		var q contribution.CommandRequest
		if e := decode(r, &q); e != nil {
			return nil, e
		}
		return s.Command(r.Context(), p, r.PathValue("id"), r.Header.Get("Idempotency-Key"), q)
	})
	return m, nil
}
func checkQuery(r *http.Request, allowed ...string) error {
	if r.URL.RawQuery == "" {
		return nil
	}
	parsed, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return contribution.ErrInput
	}
	for k, vs := range parsed {
		if k == "" || len(vs) != 1 || !slices.Contains(allowed, k) {
			return contribution.ErrInput
		}
	}
	return nil
}
func pageSize(r *http.Request) (int, error) {
	n := 20
	if r.URL.Query().Has("limit") {
		var e error
		n, e = strconv.Atoi(r.URL.Query().Get("limit"))
		if e != nil {
			return 0, contribution.ErrInput
		}
	}
	return n, nil
}
func decode(r *http.Request, out any) error {
	typ, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || typ != "application/json" {
		return contribution.ErrInput
	}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return contribution.ErrInput
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return contribution.ErrInput
	}
	return nil
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, code string) {
	write(w, status, struct {
		Code string `json:"code"`
	}{code})
}
func failure(w http.ResponseWriter, e error) {
	status := 503
	code := contribution.ErrUnavailable.Error()
	switch {
	case errors.Is(e, contribution.ErrInput):
		status = 400
		code = e.Error()
	case errors.Is(e, contribution.ErrDenied):
		status = 403
		code = e.Error()
	case errors.Is(e, contribution.ErrNotFound):
		status = 404
		code = e.Error()
	case errors.Is(e, contribution.ErrConflict):
		status = 409
		code = e.Error()
	}
	problem(w, status, code)
}
