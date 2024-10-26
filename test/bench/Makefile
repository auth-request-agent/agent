# Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

generate:
	go run gen.go

run-test:
	k6 run --summary-trend-stats "max,p(95),p(99),p(99.99)" load.js