package park

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParkRoundTrip(t *testing.T) {
	dir := t.TempDir()
	today := uint32(20000)
	set, err := Load(dir, "com", 7)
	if err != nil {
		t.Fatal(err)
	}
	h := Hash("example.com")
	set.Park(h, today+90)
	set.Park(Hash("expired.com"), today-1)
	if err := set.Save(dir, "com", 7, today); err != nil {
		t.Fatal(err)
	}

	again, err := Load(dir, "com", 7)
	if err != nil {
		t.Fatal(err)
	}
	if !again.Active(h, today) {
		t.Fatal("parked name should be active")
	}
	if again.Active(h, today+91) {
		t.Fatal("parked name should have expired")
	}
	if again.Active(Hash("expired.com"), today) {
		t.Fatal("an expiry in the past must not survive a save")
	}
	if _, err := os.Stat(filepath.Join(dir, "com", "s007.bin")); err != nil {
		t.Fatalf("shard file missing: %v", err)
	}
}

func TestShardIsStable(t *testing.T) {
	a, b := Hash("example.com"), Hash("example.com")
	if a != b {
		t.Fatal("hash must be deterministic across runs, or parking never matches")
	}
	if Shard(a) < 0 || Shard(a) >= Shards {
		t.Fatalf("shard out of range: %d", Shard(a))
	}
}
