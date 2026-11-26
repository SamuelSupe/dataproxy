package guard

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

const fileSecretCacheTTL = 5 * time.Second

type cachedFileSecret struct {
	val       string
	expiresAt time.Time
}

var (
	secretCacheMu sync.RWMutex
	secretCache   = make(map[string]cachedFileSecret)
)

// ResolveSecret resolves a local tenant secret value without ever sending it to the hub.
// Supported prefixes:
//   - "env:VAR_NAME"       -> reads from local process environment variable
//   - "file:/path/to/file" -> reads from local secret file with 5s TTL cache (K8s Secret / Vault Agent friendly)
//   - "literal:value"      -> explicit literal value
//   - plain string         -> treated as literal value (for local dev convenience)
func ResolveSecret(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil
	}
	switch {
	case strings.HasPrefix(spec, "env:"):
		name := strings.TrimSpace(strings.TrimPrefix(spec, "env:"))
		if name == "" {
			return "", fmt.Errorf("empty environment variable name in %q", spec)
		}
		val, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", name)
		}
		return val, nil

	case strings.HasPrefix(spec, "file:"):
		path := strings.TrimSpace(strings.TrimPrefix(spec, "file:"))
		if path == "" {
			return "", fmt.Errorf("empty secret file path in %q", spec)
		}
		now := time.Now()
		secretCacheMu.RLock()
		if entry, ok := secretCache[path]; ok && now.Before(entry.expiresAt) {
			secretCacheMu.RUnlock()
			return entry.val, nil
		}
		secretCacheMu.RUnlock()

		// Double-checked write lock prevents thundering-herd os.ReadFile storms under high QPS.
		secretCacheMu.Lock()
		defer secretCacheMu.Unlock()
		now = time.Now()
		if entry, ok := secretCache[path]; ok && now.Before(entry.expiresAt) {
			return entry.val, nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read secret file %q: %w", path, err)
		}
		val := strings.TrimRight(string(data), "\r\n")
		if len(secretCache) >= 256 {
			for k, v := range secretCache {
				if !now.Before(v.expiresAt) {
					delete(secretCache, k)
				}
			}
		}
		secretCache[path] = cachedFileSecret{val: val, expiresAt: now.Add(fileSecretCacheTTL)}
		return val, nil

	case strings.HasPrefix(spec, "literal:"):
		return strings.TrimPrefix(spec, "literal:"), nil

	default:
		return spec, nil
	}
}

// ResolveHeaderTemplate resolves an HTTP header value that may contain a prefix
// before a secret reference, e.g.:
//   - "Bearer env:ERP_API_TOKEN"  -> "Bearer <value>"
//   - "Token file:/run/secrets/k" -> "Token <value>"
//   - "env:X_API_KEY"             -> "<value>"
func ResolveHeaderTemplate(tmpl string) (string, error) {
	raw := strings.TrimSpace(tmpl)
	if raw == "" {
		return "", nil
	}
	if strings.HasPrefix(raw, "env:") || strings.HasPrefix(raw, "file:") || strings.HasPrefix(raw, "literal:") {
		return ResolveSecret(raw)
	}
	if scheme, rest, ok := strings.Cut(raw, " "); ok {
		rest = strings.TrimSpace(rest)
		if strings.HasPrefix(rest, "env:") || strings.HasPrefix(rest, "file:") || strings.HasPrefix(rest, "literal:") {
			resolved, err := ResolveSecret(rest)
			if err != nil {
				return "", err
			}
			return scheme + " " + resolved, nil
		}
	}
	return raw, nil
}
