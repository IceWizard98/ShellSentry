package core

// LineComplete reports whether a command line is a complete shell command:
// balanced single/double quotes and parentheses, and no trailing
// line-continuation backslash. It is a HEURISTIC, not a full shell parser — it
// does not track here-documents (<<EOF) or every exotic continuation, which
// remain a documented gap. Its job is to reject the common footguns
// (echo 'oops, a trailing \, an unbalanced paren) that would otherwise let the
// injected sentinel be swallowed as shell continuation and hang the session.
// Returns (true, "") when complete, or (false, reason) when not.
func LineComplete(line string) (bool, string) {
	var inSingle, inDouble, escaped bool
	parenDepth := 0
	for _, r := range line {
		switch {
		case escaped:
			// Previous char was an unescaped backslash; this char is literal.
			escaped = false
		case r == '\\' && !inSingle:
			// Single quotes take everything literally (no escapes); elsewhere a
			// backslash escapes the next char.
			escaped = true
		case inSingle:
			if r == '\'' {
				inSingle = false
			}
		case inDouble:
			if r == '"' {
				inDouble = false
			}
		case r == '\'':
			inSingle = true
		case r == '"':
			inDouble = true
		case r == '(':
			parenDepth++
		case r == ')':
			if parenDepth > 0 {
				parenDepth--
			}
		}
	}
	switch {
	case inSingle:
		return false, "unterminated single quote"
	case inDouble:
		return false, "unterminated double quote"
	case escaped:
		return false, "trailing backslash (line continuation)"
	case parenDepth > 0:
		return false, "unbalanced parenthesis"
	}
	return true, ""
}
