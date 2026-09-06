package domain

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

type diskMapping struct{ Gateway, Domain, IP string }

// AllocationStore makes DNS allocation state durable. It is deliberately used
// only by the DNS authority; gateways recover names through PTR instead of
// reading this state.
type AllocationStore interface {
	Load(context.Context, *Allocator) error
	Save(context.Context, *Allocator) error
	Allocate(context.Context, *Allocator, string, netip.Prefix, string) (netip.Addr, error)
	Lookup(context.Context, *Allocator, netip.Addr) (Mapping, bool, error)
}

// SQLStore persists allocations in either SQLite or PostgreSQL. It can be
// shared by DNS restarts, but there must still be one active DNS authority.
type SQLStore struct {
	db       *sql.DB
	postgres bool
	mu       sync.Mutex
}

// OpenAllocationStore selects storage solely from databaseURL. Supported forms
// are sqlite://file/path (relative) and postgres://user:pass@host/database.
func OpenAllocationStore(ctx context.Context, databaseURL string) (*SQLStore, error) {
	u, err := url.Parse(databaseURL)
	if err != nil {
		return nil, err
	}
	var driver, dsn string
	store := &SQLStore{}
	switch u.Scheme {
	case "sqlite":
		driver = "sqlite"
		dsn, err = sqlitePath(u)
		if err != nil {
			return nil, err
		}
	case "postgres":
		driver, dsn, store.postgres = "pgx", databaseURL, true
	default:
		return nil, fmt.Errorf("unsupported database scheme %q (want sqlite or postgres)", u.Scheme)
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	store.db = db
	if !store.postgres {
		if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
			db.Close()
			return nil, err
		}
	}
	ipType := "TEXT"
	if store.postgres {
		ipType = "INET"
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS domain_gateway_allocations (
		gateway TEXT NOT NULL,
		domain TEXT NOT NULL,
		ip `+ipType+` NOT NULL UNIQUE,
		PRIMARY KEY (gateway, domain)
	)`); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func sqlitePath(u *url.URL) (string, error) {
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("sqlite URL must contain only a file path")
	}
	if u.Host == "" {
		if u.Path == "" {
			return "", fmt.Errorf("sqlite URL has no file path")
		}
		return u.Path, nil // sqlite:///absolute/path
	}
	path := u.Host
	if tail := strings.TrimPrefix(u.Path, "/"); tail != "" {
		path += "/" + tail
	}
	return path, nil // sqlite://relative/path
}

func (s *SQLStore) Close() error { return s.db.Close() }

func (s *SQLStore) Load(ctx context.Context, a *Allocator) error {
	query := `SELECT gateway, domain, ip FROM domain_gateway_allocations`
	if s.postgres {
		query = `SELECT gateway, domain, host(ip) FROM domain_gateway_allocations`
	}
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	a.mu.Lock()
	defer a.mu.Unlock()
	for rows.Next() {
		var row diskMapping
		if err := rows.Scan(&row.Gateway, &row.Domain, &row.IP); err != nil {
			return err
		}
		ip, err := netip.ParseAddr(row.IP)
		if err != nil {
			return fmt.Errorf("invalid PostgreSQL allocation %q: %w", row.IP, err)
		}
		a.byKey[row.Gateway+"\x00"+row.Domain] = ip
		a.byIP[ip] = Mapping{row.Gateway, row.Domain}
		if next := ip.Next(); !a.next[row.Gateway].IsValid() || a.next[row.Gateway].Less(next) {
			a.next[row.Gateway] = next
		}
	}
	return rows.Err()
}

func (s *SQLStore) Save(ctx context.Context, a *Allocator) error {
	// Serializing snapshots prevents two concurrent DNS requests from making a
	// later write omit an allocation that an earlier request had observed.
	s.mu.Lock()
	defer s.mu.Unlock()
	a.mu.RLock()
	rows := make([]diskMapping, 0, len(a.byIP))
	for ip, m := range a.byIP {
		rows = append(rows, diskMapping{m.Gateway, m.Domain, ip.String()})
	}
	a.mu.RUnlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement := `INSERT INTO domain_gateway_allocations (gateway, domain, ip)
		VALUES (?, ?, ?)
		ON CONFLICT (gateway, domain) DO UPDATE SET ip = excluded.ip`
	if s.postgres {
		statement = `INSERT INTO domain_gateway_allocations (gateway, domain, ip)
			VALUES ($1, $2, $3::inet)
			ON CONFLICT (gateway, domain) DO UPDATE SET ip = EXCLUDED.ip`
	}
	for _, row := range rows {
		if _, err := tx.ExecContext(ctx, statement, row.Gateway, row.Domain, row.IP); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Allocate makes the SQL registry the allocation authority. The unique
// gateway/domain and IP constraints make concurrent DNS authorities converge
// on one stable address without sharing process memory.
func (s *SQLStore) Allocate(ctx context.Context, a *Allocator, gateway string, prefix netip.Prefix, domain string) (netip.Addr, error) {
	if ip, ok := a.LookupKey(gateway, domain); ok {
		return ip, nil
	}
	for ip := prefix.Masked().Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		statement := `INSERT INTO domain_gateway_allocations (gateway, domain, ip)
			VALUES (?, ?, ?)
			ON CONFLICT DO NOTHING`
		if s.postgres {
			statement = `INSERT INTO domain_gateway_allocations (gateway, domain, ip)
				VALUES ($1, $2, $3::inet)
				ON CONFLICT DO NOTHING`
		}
		result, err := s.db.ExecContext(ctx, statement, gateway, domain, ip.String())
		if err != nil {
			return netip.Addr{}, err
		}
		inserted, err := result.RowsAffected()
		if err != nil {
			return netip.Addr{}, err
		}
		var value string
		query := `SELECT ip FROM domain_gateway_allocations WHERE gateway = ? AND domain = ?`
		if s.postgres {
			query = `SELECT host(ip) FROM domain_gateway_allocations WHERE gateway = $1 AND domain = $2`
		}
		err = s.db.QueryRowContext(ctx, query, gateway, domain).Scan(&value)
		if errors.Is(err, sql.ErrNoRows) && inserted == 0 {
			// This address belongs to another domain. Try the next address;
			// the unique IP constraint remains the cross-replica arbiter.
			continue
		}
		if err != nil {
			return netip.Addr{}, err
		}
		allocated, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Addr{}, err
		}
		a.Remember(gateway, domain, allocated)
		return allocated, nil
	}
	return netip.Addr{}, fmt.Errorf("synthetic prefix exhausted")
}

// Lookup fills a replica's local PTR cache from the shared allocation registry.
func (s *SQLStore) Lookup(ctx context.Context, a *Allocator, ip netip.Addr) (Mapping, bool, error) {
	if mapping, ok := a.Lookup(ip); ok {
		return mapping, true, nil
	}
	var mapping Mapping
	query := `SELECT gateway, domain FROM domain_gateway_allocations WHERE ip = ?`
	if s.postgres {
		query = `SELECT gateway, domain FROM domain_gateway_allocations WHERE ip = $1::inet`
	}
	err := s.db.QueryRowContext(ctx, query, ip.String()).Scan(&mapping.Gateway, &mapping.Domain)
	if errors.Is(err, sql.ErrNoRows) {
		return Mapping{}, false, nil
	}
	if err != nil {
		return Mapping{}, false, err
	}
	a.Remember(mapping.Gateway, mapping.Domain, ip)
	return mapping, true, nil
}

func (a *Allocator) Load(path string) error {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var rows []diskMapping
	if err = json.Unmarshal(b, &rows); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, r := range rows {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil {
			return err
		}
		a.byKey[r.Gateway+"\x00"+r.Domain] = ip
		a.byIP[ip] = Mapping{r.Gateway, r.Domain}
		if next := ip.Next(); !a.next[r.Gateway].IsValid() || a.next[r.Gateway].Less(next) {
			a.next[r.Gateway] = next
		}
	}
	return nil
}
func (a *Allocator) Save(path string) error {
	a.persistMu.Lock()
	defer a.persistMu.Unlock()
	a.mu.RLock()
	rows := make([]diskMapping, 0, len(a.byIP))
	for ip, m := range a.byIP {
		rows = append(rows, diskMapping{m.Gateway, m.Domain, ip.String()})
	}
	a.mu.RUnlock()
	b, err := json.Marshal(rows)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
