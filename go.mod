module github.com/moby/policy-helpers

go 1.24.3

require (
	github.com/containerd/containerd/v2 v2.2.0-rc.0
	github.com/containerd/errdefs v1.0.0
	github.com/containerd/platforms v1.0.0-rc.1
	github.com/distribution/reference v0.6.0
	github.com/gofrs/flock v0.13.0
	github.com/in-toto/in-toto-golang v0.9.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/sigstore/protobuf-specs v0.5.0
	github.com/sigstore/sigstore v1.9.6-0.20250729224751-181c5d3339b3
	github.com/sigstore/sigstore-go v1.1.3
	github.com/theupdateframework/go-tuf/v2 v2.2.0
	golang.org/x/sync v0.17.0
)

require (
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/typeurl/v2 v2.2.3 // indirect
	github.com/cyberphone/json-canonicalization v0.0.0-20241213102144-19d51d7fe467 // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230818184609-3a137a874352 // indirect
	github.com/digitorus/timestamp v0.0.0-20231217203849-220c5c2851b7 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/analysis v0.24.0 // indirect
	github.com/go-openapi/errors v0.22.3 // indirect
	github.com/go-openapi/jsonpointer v0.22.1 // indirect
	github.com/go-openapi/jsonreference v0.21.2 // indirect
	github.com/go-openapi/loads v0.23.1 // indirect
	github.com/go-openapi/runtime v0.29.0 // indirect
	github.com/go-openapi/spec v0.22.0 // indirect
	github.com/go-openapi/strfmt v0.24.0 // indirect
	github.com/go-openapi/swag v0.24.1 // indirect
	github.com/go-openapi/swag/cmdutils v0.24.0 // indirect
	github.com/go-openapi/swag/conv v0.25.1 // indirect
	github.com/go-openapi/swag/fileutils v0.25.1 // indirect
	github.com/go-openapi/swag/jsonname v0.25.1 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.1 // indirect
	github.com/go-openapi/swag/loading v0.25.1 // indirect
	github.com/go-openapi/swag/mangling v0.25.1 // indirect
	github.com/go-openapi/swag/netutils v0.24.0 // indirect
	github.com/go-openapi/swag/stringutils v0.25.1 // indirect
	github.com/go-openapi/swag/typeutils v0.25.1 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.1 // indirect
	github.com/go-openapi/validate v0.25.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/certificate-transparency-go v1.3.2 // indirect
	github.com/google/go-containerregistry v0.20.6 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.2 // indirect
	github.com/in-toto/attestation v1.1.2 // indirect
	github.com/klauspost/compress v1.18.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/oklog/ulid v1.3.1 // indirect
	github.com/secure-systems-lab/go-securesystemslib v0.9.1 // indirect
	github.com/shibumi/go-pathspec v1.3.0 // indirect
	github.com/sigstore/rekor v1.4.2 // indirect
	github.com/sigstore/rekor-tiles v0.1.11 // indirect
	github.com/sigstore/timestamp-authority v1.2.9 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/transparency-dev/formats v0.0.0-20250421220931-bb8ad4d07c26 // indirect
	github.com/transparency-dev/merkle v0.0.2 // indirect
	go.mongodb.org/mongo-driver v1.17.4 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel v1.38.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.opentelemetry.io/otel/trace v1.38.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.29.0 // indirect
	golang.org/x/net v0.44.0 // indirect
	golang.org/x/sys v0.37.0 // indirect
	golang.org/x/term v0.35.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250818200422-3122310a409c // indirect
	google.golang.org/grpc v1.76.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace (
	// These branches contain cherry-picked patches proposed to upstream repos for reducing the imported dependency set.
	// They are fully backwards compatible and code in this module works the same way with or without these patches.
	github.com/sigstore/rekor => github.com/tonistiigi/rekor v0.0.0-20251105052018-99cef2885dd7
	github.com/sigstore/rekor-tiles => github.com/tonistiigi/rekor-tiles v0.0.0-20251105010948-ccca386fbeb0
	github.com/sigstore/sigstore => github.com/tonistiigi/sigstore v0.0.0-20251105013205-e8108809ccc2
)
