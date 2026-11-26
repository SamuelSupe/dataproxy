package guard

import (
	"strings"
	"sync"
)

var sqlTokenPool = sync.Pool{
	New: func() any {
		s := make([]string, 0, 32)
		return &s
	},
}

func getSQLTokens() *[]string {
	p := sqlTokenPool.Get().(*[]string)
	*p = (*p)[:0]
	return p
}

func putSQLTokens(p *[]string) {
	if p == nil || cap(*p) > 256 {
		return
	}
	s := *p
	clear(s)
	*p = s[:0]
	sqlTokenPool.Put(p)
}

var safeMySQLSetVars = []string{
	"AUTOCOMMIT",
	"TIME_ZONE",
	"SQL_MODE",
	"NET_WRITE_TIMEOUT",
	"NET_READ_TIMEOUT",
	"MAX_EXECUTION_TIME",
	"GROUP_CONCAT_MAX_LEN",
	"CHARACTER_SET_RESULTS",
	"CHARACTER_SET_CLIENT",
	"CHARACTER_SET_CONNECTION",
}

var mutatingCTEKeywords = []string{
	"INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "DROP", "ALTER", "CREATE", "TRUNCATE",
}

// IsReadOnlySQL performs a strict lexical & structural check to ensure a MySQL
// query is strictly read-only (safe for tenant-side Read-Only Guard) with zero
// heap allocations on the normal query fast path.
func IsReadOnlySQL(sql string) (bool, string) {
	bufPtr := getSQLTokens()
	defer putSQLTokens(bufPtr)
	tokens := tokenizeSQLInto(sql, *bufPtr)
	*bufPtr = tokens
	return isReadOnlySQLTokens(tokens)
}

func isReadOnlySQLTokens(tokens []string) (bool, string) {
	if len(tokens) == 0 {
		return true, ""
	}

	// 1. Block multi-statement queries: reject any semicolon followed by another token.
	for i, tok := range tokens {
		if tok == ";" && i < len(tokens)-1 {
			return false, "multi-statement SQL is blocked in read-only mode"
		}
	}
	if tokens[len(tokens)-1] == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	if len(tokens) == 0 {
		return true, ""
	}

	first := tokens[0]
	switch {
	case strings.EqualFold(first, "SELECT"),
		strings.EqualFold(first, "SHOW"),
		strings.EqualFold(first, "DESCRIBE"),
		strings.EqualFold(first, "DESC"),
		strings.EqualFold(first, "EXPLAIN"),
		strings.EqualFold(first, "USE"):
		if reason := checkForbiddenSelectClauses(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "WITH"):
		// Common Table Expression: ensure no mutating top-level DML keyword appears.
		for _, tok := range tokens[1:] {
			for _, kw := range mutatingCTEKeywords {
				if strings.EqualFold(tok, kw) {
					return false, "mutating CTE (" + kw + ") is blocked in read-only mode"
				}
			}
		}
		if reason := checkForbiddenSelectClauses(tokens); reason != "" {
			return false, reason
		}
		return true, ""

	case strings.EqualFold(first, "SET"):
		// Allow safe session-level settings required by JDBC / Go / Python MySQL drivers.
		if isSafeReadOnlySet(tokens) {
			return true, ""
		}
		return false, "non-whitelisted SET statement is blocked in read-only mode"

	case strings.EqualFold(first, "START"):
		// Allow "START TRANSACTION READ ONLY" only.
		if len(tokens) >= 4 &&
			strings.EqualFold(tokens[1], "TRANSACTION") &&
			strings.EqualFold(tokens[2], "READ") &&
			strings.EqualFold(tokens[3], "ONLY") {
			return true, ""
		}
		return false, "read-write transaction is blocked in read-only mode"

	case strings.EqualFold(first, "COMMIT"), strings.EqualFold(first, "ROLLBACK"):
		// Benign transaction end markers for read-only transactions.
		return true, ""

	default:
		return false, "SQL command " + strings.ToUpper(first) + " is blocked by tenant read-only policy"
	}
}

func checkForbiddenSelectClauses(tokens []string) string {
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if len(tok) == 4 && strings.EqualFold(tok, "INTO") && i+1 < len(tokens) {
			next := tokens[i+1]
			if strings.EqualFold(next, "OUTFILE") {
				return "SELECT INTO OUTFILE is blocked in read-only mode"
			}
			if strings.EqualFold(next, "DUMPFILE") {
				return "SELECT INTO DUMPFILE is blocked in read-only mode"
			}
		}
		if len(tok) == 3 && strings.EqualFold(tok, "FOR") && i+1 < len(tokens) && strings.EqualFold(tokens[i+1], "UPDATE") {
			return "SELECT ... FOR UPDATE is blocked in read-only mode"
		}
		if len(tok) == 4 && strings.EqualFold(tok, "LOCK") && i+3 < len(tokens) &&
			strings.EqualFold(tokens[i+1], "IN") &&
			strings.EqualFold(tokens[i+2], "SHARE") &&
			strings.EqualFold(tokens[i+3], "MODE") {
			return "SELECT ... LOCK IN SHARE MODE is blocked in read-only mode"
		}
	}
	return ""
}

func isSafeReadOnlySet(tokens []string) bool {
	if len(tokens) < 2 {
		return false
	}
	// Never allow GLOBAL / PERSIST mutations.
	for _, tok := range tokens[1:] {
		if strings.EqualFold(tok, "GLOBAL") ||
			strings.EqualFold(tok, "PERSIST") ||
			strings.EqualFold(tok, "PERSIST_ONLY") ||
			(len(tok) >= 8 && strings.EqualFold(tok[:8], "@@GLOBAL")) {
			return false
		}
	}
	second := tokens[1]
	switch {
	case strings.EqualFold(second, "NAMES"),
		strings.EqualFold(second, "CHARACTER"),
		strings.EqualFold(second, "CHARSET"):
		return true
	case strings.EqualFold(second, "SESSION"), strings.EqualFold(second, "TRANSACTION"):
		for _, tok := range tokens[1:] {
			if strings.EqualFold(tok, "WRITE") {
				return false
			}
		}
		return true
	default:
		varName := second
		if len(varName) >= 10 && strings.EqualFold(varName[:10], "@@SESSION.") {
			varName = varName[10:]
		} else if strings.HasPrefix(varName, "@@") {
			varName = varName[2:]
		}
		for _, sv := range safeMySQLSetVars {
			if strings.EqualFold(varName, sv) {
				return true
			}
		}
		return false
	}
}

// tokenizeSQL extracts SQL keywords, identifiers, and semicolons while stripping
// comments and replacing string literals with a placeholder token so keywords
// inside string literals (e.g. WHERE action = 'DELETE') do not trigger false positives.
func tokenizeSQL(sql string) []string {
	return tokenizeSQLInto(sql, make([]string, 0, 16))
}

func tokenizeSQLInto(sql string, tokens []string) []string {
	n := len(sql)
	i := 0
	for i < n {
		ch := sql[i]

		// Fast ASCII whitespace skip.
		if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\f' || ch == '\v' {
			i++
			continue
		}

		// Line comment: -- ... or # ...
		if ch == '#' || (ch == '-' && i+1 < n && sql[i+1] == '-') {
			for i < n && sql[i] != '\n' {
				i++
			}
			continue
		}

		// Block comment: /* ... */
		// Note: MySQL conditional comments /*!50000 ... */ are executed by MySQL, so
		// we must NOT blindly discard them—treat /*! as executable content!
		if ch == '/' && i+1 < n && sql[i+1] == '*' {
			if i+2 < n && sql[i+2] == '!' {
				// Strip opening /*!digits and keep inner SQL tokens visible!
				i += 3
				for i < n && sql[i] >= '0' && sql[i] <= '9' {
					i++
				}
				continue
			}
			i += 2
			for i+1 < n && !(sql[i] == '*' && sql[i+1] == '/') {
				i++
			}
			i += 2
			continue
		}
		if ch == '*' && i+1 < n && sql[i+1] == '/' {
			i += 2
			continue
		}

		// Quoted string literal ('...' or "..."): collapse into placeholder.
		if ch == '\'' || ch == '"' {
			quote := ch
			i++
			for i < n {
				if sql[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if sql[i] == quote {
					if i+1 < n && sql[i+1] == quote {
						i += 2 // escaped doubled quote
						continue
					}
					i++
					break
				}
				i++
			}
			tokens = append(tokens, "<STR>")
			continue
		}

		// Backtick identifier (`table`): read identifier.
		if ch == '`' {
			start := i + 1
			i++
			for i < n && sql[i] != '`' {
				i++
			}
			tokens = append(tokens, sql[start:i])
			if i < n {
				i++
			}
			continue
		}

		// Semicolon statement separator.
		if ch == ';' {
			tokens = append(tokens, ";")
			i++
			continue
		}

		// Word / keyword / variable (alphanumeric, _, @, .).
		if isWordChar(ch) {
			start := i
			for i < n && isWordChar(sql[i]) {
				i++
			}
			tokens = append(tokens, sql[start:i])
			continue
		}

		// Skip punctuation/operators (=, (, ), ,, +, etc.)
		i++
	}
	return tokens
}

func isWordChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '_' || ch == '@' || ch == '.'
}
