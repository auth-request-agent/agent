# Copyright 2024 The AuthRequestAgent Authors.  All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

FROM alpine:3.20 

ARG TARGETOS
ARG TARGETARCH

COPY dist/opa_${TARGETOS}_${TARGETARCH}_static /opa

ENTRYPOINT ["/opa"]
CMD ["run"]