package core

import "strings"

// NoPathIndex is the path_index value when a command has no path argument.
const NoPathIndex = 9999999

// DetectPath returns the first path-like argument (starts with / ~ ./ .. or
// contains /). No filesystem access. args excludes the command word itself.
func DetectPath(args []string) (string, bool) {
	for _, a := range args {
		if isPathLike(a) {
			return a, true
		}
	}
	return "", false
}

func isPathLike(a string) bool {
	if a == "" {
		return false
	}
	if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~") ||
		strings.HasPrefix(a, "./") || strings.HasPrefix(a, "../") {
		return true
	}
	return strings.Contains(a, "/")
}
