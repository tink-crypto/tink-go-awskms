module github.com/tink-crypto/tink-go-awskms/v2

go 1.19

require (
	github.com/aws/aws-sdk-go v1.44.267
	// NOTE: The tag doesn't exist, yet this is needed since we keep compatibility with the top of
	// tink-go's main branch. Gomod tests add a replace directive to use a local tink-go repository.
	// TODO(b/204159796): Update this once tink-go release is complete.
	github.com/tink-crypto/tink-go/v2 v2.0.0
)

require (
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)
