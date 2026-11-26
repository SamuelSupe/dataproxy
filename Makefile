.PHONY: build test vet certs clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/dataproxy-hub ./cmd/dataproxy-hub
	go build -ldflags "$(LDFLAGS)" -o bin/dataproxy-agent ./cmd/dataproxy-agent

build-linux-amd64:
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/dataproxy-hub-linux-amd64 ./cmd/dataproxy-hub
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/dataproxy-agent-linux-amd64 ./cmd/dataproxy-agent

vet:
	go vet ./...

test:
	go test -v -race -count=1 ./...

test-orbstack: build
	./scripts/verify_orbstack.sh

# 生成本地开发测试用自签 CA、Hub 服务端证书及租户 mTLS 客户端证书
certs:
	mkdir -p certs
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout certs/ca.key -out certs/ca.crt -days 365 \
		-subj "/CN=dataproxy-dev-ca"
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout certs/hub.key -out certs/hub.csr \
		-subj "/CN=localhost" \
		-addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
	openssl x509 -req -in certs/hub.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
		-out certs/hub.crt -days 365 \
		-copy_extensions copy
	openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
		-keyout certs/tenant-acme.key -out certs/tenant-acme.csr \
		-subj "/CN=tenant-acme" \
		-addext "subjectAltName=URI:spiffe://dataproxy/tenant/tenant-acme"
	openssl x509 -req -in certs/tenant-acme.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial \
		-out certs/tenant-acme.crt -days 365 \
		-copy_extensions copy
	rm -f certs/*.csr certs/*.srl

clean:
	rm -rf bin certs
