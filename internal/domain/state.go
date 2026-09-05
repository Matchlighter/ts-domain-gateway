package domain

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
)

type diskMapping struct{ Gateway, Domain, IP string }

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
