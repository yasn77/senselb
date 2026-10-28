package opnsense

import "strings"

// Ownership markers. senselb only mutates an object that carries both the name
// prefix and the exact description, so another tool using a senselb-like name
// is never adopted by accident.
const (
	// OwnedPrefix starts the name of every object senselb creates.
	OwnedPrefix = "senselb-"
	// OwnedDescription is the description senselb stamps on its objects.
	OwnedDescription = "managed by senselb — do not edit"
)

// IsOwned reports whether name and description mark an object as managed by
// senselb. Both must match: a prefixed name alone is a name collision, not
// ownership.
func IsOwned(name, description string) bool {
	return strings.HasPrefix(name, OwnedPrefix) && description == OwnedDescription
}

// OwnedName builds the deterministic name of a senselb-managed object from its
// parts, for example OwnedName("web", "prod", "80") == "senselb-web-prod-80".
// Parts are lowercased and joined with hyphens.
//
// OwnedName returns "" when no parts are given or when any part is empty: a
// caller must not create a name it cannot parse back. It rejects rather than
// trims, so a blank part is a bug in the caller.
func OwnedName(parts ...string) string {
	if len(parts) == 0 {
		return ""
	}
	lowered := make([]string, len(parts))
	for i, part := range parts {
		if part == "" {
			return ""
		}
		lowered[i] = strings.ToLower(part)
	}
	return OwnedPrefix + strings.Join(lowered, "-")
}
