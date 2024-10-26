# Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

OPA_VERSION ?= "0.69.0" 
GOARCH ?= $(shell go env GOARCH)
GOOS ?= $(shell go env GOOS)

build-opa:
	docker build --build-arg="TARGETOS=${GOOS}" --build-arg="TARGETARCH=${GOARCH}" -t opa-test:${OPA_VERSION} .

generate:
	go run gen.go

build-bundle: generate
	opa build -b ./bundle

run-test:
	k6 run --summary-trend-stats "max,p(95),p(99),p(99.99)" load.js