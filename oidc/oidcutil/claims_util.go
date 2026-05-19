package oidcutil

// HasNonEmptyString returns true if the map contains a string value for the
// given key that is not empty.
func HasNonEmptyString(m map[string]any, key string) bool {
	v, ok := m[key]
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && s != ""
}

// HasAnyNonEmptyString returns true if any of the provided keys in the map
// contain a non-empty string value.
func HasAnyNonEmptyString(m map[string]any, keys ...string) bool {
	for _, k := range keys {
		if HasNonEmptyString(m, k) {
			return true
		}
	}
	return false
}
