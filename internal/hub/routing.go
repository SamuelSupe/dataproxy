package hub

import (
	"fmt"
	"net"
	"strings"
)

// ParseVirtualTarget extracts (tenantID, serviceName) from a virtual host or host:port
// with zero heap allocations on standard lowercase hostnames.
// Supported forms:
//  1. "<service>.<tenant>.<suffix>[:port]" (e.g., "mysql-orders.tenant-a.dataproxy.internal:3306")
//  2. "<tenant>--<service>[.<suffix>][:port]" (e.g., "tenant-a--mysql-orders:3306")
func ParseVirtualTarget(hostPort, domainSuffix string) (tenantID, serviceName string, err error) {
	host := strings.TrimSpace(hostPort)
	if host == "" {
		return "", "", fmt.Errorf("empty virtual host")
	}
	if strings.IndexByte(host, ':') >= 0 {
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
	}
	host = strings.TrimSuffix(toLowerASCIIFast(strings.TrimSpace(host)), ".")
	suffix := strings.TrimPrefix(toLowerASCIIFast(strings.TrimSpace(domainSuffix)), ".")

	if suffix != "" && len(host) > len(suffix)+1 && host[len(host)-len(suffix)-1] == '.' && host[len(host)-len(suffix):] == suffix {
		prefix := host[:len(host)-len(suffix)-1]
		if t, s, ok := splitTenantServicePrefix(prefix); ok {
			return t, s, nil
		}
		return "", "", fmt.Errorf("invalid virtual host %q: expected <service>.<tenant>.%s", hostPort, suffix)
	}

	if t, s, ok := strings.Cut(host, "--"); ok && t != "" && s != "" && strings.IndexByte(s, '.') < 0 {
		return t, s, nil
	}

	return "", "", fmt.Errorf("virtual host %q does not match suffix .%s or <tenant>--<service>", hostPort, suffix)
}

func splitTenantServicePrefix(prefix string) (tenantID, serviceName string, ok bool) {
	if t, s, found := strings.Cut(prefix, "--"); found && t != "" && s != "" && strings.IndexByte(s, '.') < 0 {
		return t, s, true
	}
	svc, tenant, found := strings.Cut(prefix, ".")
	if found && svc != "" && tenant != "" && strings.IndexByte(tenant, '.') < 0 {
		// <service>.<tenant>.<suffix>
		return tenant, svc, true
	}
	return "", "", false
}

// toLowerASCIIFast avoids allocating a new string when s already has no uppercase ASCII letters.
func toLowerASCIIFast(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}
