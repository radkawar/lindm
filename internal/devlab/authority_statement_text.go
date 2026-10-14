// SPDX-License-Identifier: Apache-2.0

package devlab

import "strings"

const profileStatementTextLimit = 4096

// profileStatementText accepts only complete, bounded DML from the owned DB's
// pg_stat_statements, never activity.query. PostgreSQL normalization does not
// promise to remove comments or utility credentials. Strip comments and redact
// all quoted literals/identifiers anyway; reject utility or unrecognized input.
// This is a diagnostic lexer, not an SQL parser or an executable SQL rewriter.
func profileStatementText(query string) (string, bool) {
	if len(query) == 0 || len(query) > profileStatementTextLimit {
		return "", false
	}
	var result strings.Builder
	result.Grow(len(query))
	first, terminated := true, false
	for i := 0; i < len(query); {
		c := query[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' {
			i++
			continue
		}
		if strings.HasPrefix(query[i:], "--") {
			end := strings.IndexByte(query[i:], '\n')
			if end < 0 {
				break
			}
			i += end + 1
			continue
		}
		if strings.HasPrefix(query[i:], "/*") {
			i += 2
			depth := 1
			for i < len(query) && depth > 0 {
				switch {
				case strings.HasPrefix(query[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(query[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth != 0 {
				return "", false
			}
			continue
		}
		if terminated {
			return "", false
		}
		start := i
		var token string
		switch {
		case profileSQLLetter(c):
			i++
			for i < len(query) && (profileSQLLetter(query[i]) || profileSQLDigit(query[i]) || query[i] == '$') {
				i++
			}
			token = query[start:i]
			// Prefixes belong to their literal, not to a retained identifier.
			prefix := strings.ToUpper(token)
			if prefix == "U" && i+1 < len(query) && query[i] == '&' && (query[i+1] == '\'' || query[i+1] == '"') {
				i++
				prefix = "U&"
			}
			if i < len(query) && ((query[i] == '\'' && (prefix == "E" || prefix == "B" || prefix == "X" || prefix == "N" || prefix == "U&")) || (query[i] == '"' && prefix == "U&")) {
				end, ok := profileQuotedEnd(query, i)
				if !ok {
					return "", false
				}
				i, token = end, "?"
			}
		case c == '\'' || c == '"':
			end, ok := profileQuotedEnd(query, i)
			if !ok {
				return "", false
			}
			i, token = end, "?"
		case c == '$':
			i++
			if i < len(query) && profileSQLDigit(query[i]) {
				for i < len(query) && profileSQLDigit(query[i]) {
					i++
				}
				token = query[start:i]
				break
			}
			for i < len(query) && (profileSQLLetter(query[i]) || profileSQLDigit(query[i])) {
				i++
			}
			if i >= len(query) || query[i] != '$' {
				return "", false
			}
			i++
			delimiter := query[start:i]
			end := strings.Index(query[i:], delimiter)
			if end < 0 {
				return "", false
			}
			i += end + len(delimiter)
			token = "?"
		case profileSQLDigit(c):
			// Numeric literals are ordinarily already normalized. Omit their
			// entire token if a server version retains one.
			i++
			for i < len(query) && (profileSQLDigit(query[i]) || profileSQLLetter(query[i]) || query[i] == '.') {
				i++
			}
			token = "?"
		case c == ';':
			terminated = true
			i++
			continue
		case strings.ContainsRune("(),.[]", rune(c)):
			i++
			token = query[start:i]
		case strings.ContainsRune("+-*/<>=~!@#%^&|?:", rune(c)):
			i++
			for i < len(query) && strings.ContainsRune("+-*/<>=~!@#%^&|?:", rune(query[i])) && !strings.HasPrefix(query[i:], "--") && !strings.HasPrefix(query[i:], "/*") {
				i++
			}
			token = query[start:i]
		default:
			return "", false
		}
		if first {
			switch strings.ToUpper(token) {
			case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH", "MERGE":
			default:
				return "", false
			}
			first = false
		} else {
			result.WriteByte(' ')
		}
		if result.Len()+len(token) > profileStatementTextLimit {
			return "", false
		}
		result.WriteString(token)
	}
	if first {
		return "", false
	}
	return result.String(), true
}

func profileQuotedEnd(query string, start int) (int, bool) {
	quote := query[start]
	for i := start + 1; i < len(query); i++ {
		if query[i] == '\\' {
			// The originating session's standard_conforming_strings setting is
			// unavailable. Do not guess whether this escapes the closing quote:
			// omit the complete rendering rather than expose a literal suffix.
			return 0, false
		}
		if query[i] == quote {
			if i+1 < len(query) && query[i+1] == quote {
				i++
				continue
			}
			return i + 1, true
		}
	}
	return 0, false
}

func profileSQLLetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}

func profileSQLDigit(c byte) bool { return c >= '0' && c <= '9' }
