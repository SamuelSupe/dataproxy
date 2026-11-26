package hub

import (
	"fmt"
	"net"
	"strings"
)

// ParseVirtualTarget extracts (tenantID, serviceName) from a virtual host or host:port.
// Supported forms:
//  1. "<service>.<tenant>.<suffix>[:port]" (e.g., "mysql-orders.tenant-a.dataproxy.internal:3306")
//  2. "<tenant>--<service>[.<suffix>][:port]" (e.g., "tenant-a--mysql-orders:3306")
func ParseVirtualTarget(hostPort, domainSuffix string) (tenantID, serviceName string, err error) {
	host := strings.TrimSpace(hostPort)
	if host == "" {
		return "", "", fmt.Errorf("empty virtual host")
	}
	if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	suffix := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domainSuffix)), ".")

	if suffix != "" && strings.HasSuffix(host, "."+suffix) {
		prefix := strings.TrimSuffix(host, "."+suffix)
		if t, s, ok := splitTenantServicePrefix(prefix); ok {
			return t, s, nil
		}
		return "", "", fmt.Errorf("invalid virtual host %q: expected <service>.<tenant>.%s", hostPort, suffix)
	}

	if t, s, ok := strings.Cut(host, "--"); ok && t != "" && s != "" && !strings.Contains(s, ".") {
		return t, s, nil
	}

	return "", "", fmt.Errorf("virtual host %q does not match suffix .%s or <tenant>--<service>", hostPort, suffix)
}

func splitTenantServicePrefix(prefix string) (tenantID, serviceName string, ok bool) {
	if t, s, found := strings.Cut(prefix, "--"); found && t != "" && s != "" && !strings.Contains(s, ".") {
		return t, s, true
	}
	parts := strings.Split(prefix, ".")
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		// <service>.<tenant>.<suffix>
		return parts[1], parts[0], true
	}
	return "", "", false
}
