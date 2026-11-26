package hub

import "testing"

func TestParseVirtualTarget(t *testing.T) {
	cases := []struct {
		hostPort string
		suffix   string
		wantTen  string
		wantSvc  string
		wantErr  bool
	}{
		{"mysql-orders.tenant-acme.dataproxy.internal:3306", "dataproxy.internal", "tenant-acme", "mysql-orders", false},
		{"internal-erp.tenant-acme.dataproxy.internal", "dataproxy.internal", "tenant-acme", "internal-erp", false},
		{"tenant-acme--mysql-orders.dataproxy.internal:3306", "dataproxy.internal", "tenant-acme", "mysql-orders", false},
		{"tenant-acme--mysql-orders:3306", "dataproxy.internal", "tenant-acme", "mysql-orders", false},
		{"onlyone.dataproxy.internal:3306", "dataproxy.internal", "", "", true},
		{"evil.example.com:3306", "dataproxy.internal", "", "", true},
		{"", "dataproxy.internal", "", "", true},
	}

	for _, tc := range cases {
		ten, svc, err := ParseVirtualTarget(tc.hostPort, tc.suffix)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseVirtualTarget(%q) expected error, got (%q, %q)", tc.hostPort, ten, svc)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseVirtualTarget(%q) unexpected error: %v", tc.hostPort, err)
			continue
		}
		if ten != tc.wantTen || svc != tc.wantSvc {
			t.Errorf("ParseVirtualTarget(%q) = (%q, %q), want (%q, %q)", tc.hostPort, ten, svc, tc.wantTen, tc.wantSvc)
		}
	}
}
