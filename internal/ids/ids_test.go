package ids

import "testing"

func TestNewIsValidV4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := New()
		if !Valid(id) {
			t.Fatalf("invalid id %q", id)
		}
		if id[14] != '4' {
			t.Fatalf("not version 4: %q", id)
		}
		if c := id[19]; c != '8' && c != '9' && c != 'a' && c != 'b' {
			t.Fatalf("bad variant: %q", id)
		}
		if seen[id] {
			t.Fatalf("duplicate %q", id)
		}
		seen[id] = true
	}
}

func TestValid(t *testing.T) {
	for _, s := range []string{"", "not-a-uuid", "123e4567-e89b-12d3-a456-42661417400", "123e4567xe89b-12d3-a456-426614174000", "123e4567-e89b-12d3-a456-42661417400g"} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
	if !Valid("123E4567-e89b-12d3-a456-426614174000") {
		t.Error("expected valid")
	}
}
