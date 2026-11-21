// Package park remembers which names were decided with no need to look again for
// a while: no DNS answer, no port open, no security.txt found.
//
// The whole point is memory. A .com zone is ~160M names and a parked set of that
// size will not fit in RAM, so the set is sharded 4096 ways by the top bits of a
// 64-bit hash of the name and only one shard is resident at a time (~40k names).
// Records are sorted by hash and expire on a day number, so a stale decision falls
// out on its own without a separate sweep.
package park

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const Shards = 4096

func Hash(name string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return h.Sum64()
}

func Shard(h uint64) int { return int(h >> 52) } // top 12 bits

type Set struct {
	mu      sync.Mutex
	entries map[uint64]uint32
}

func Load(dir, tld string, shard int) (*Set, error) {
	s := &Set{entries: make(map[uint64]uint32)}
	path := filepath.Join(dir, tld, shardName(shard))
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	for i := 0; i+12 <= len(data); i += 12 {
		h := binary.LittleEndian.Uint64(data[i:])
		until := binary.LittleEndian.Uint32(data[i+8:])
		s.entries[h] = until
	}
	return s, nil
}

func (s *Set) Active(h uint64, today uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.entries[h]
	return ok && until > today
}

func (s *Set) Park(h uint64, until uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[h] = until
}

func (s *Set) Save(dir, tld string, shard int, today uint32) error {
	s.mu.Lock()
	hashes := make([]uint64, 0, len(s.entries))
	for h, until := range s.entries {
		if until > today {
			hashes = append(hashes, h)
		}
	}
	s.mu.Unlock()
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })
	buf := make([]byte, 0, len(hashes)*12)
	for _, h := range hashes {
		buf = binary.LittleEndian.AppendUint64(buf, h)
		s.mu.Lock()
		buf = binary.LittleEndian.AppendUint32(buf, s.entries[h])
		s.mu.Unlock()
	}
	dir = filepath.Join(dir, tld)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, ".tmp-"+shardName(shard))
	if err := os.WriteFile(tmp, buf, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, shardName(shard)))
}

func shardName(shard int) string { return fmt.Sprintf("s%03x.bin", shard) }
