// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

package awskmsv2

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/tink-crypto/tink-go/v2/core/registry"
	"github.com/tink-crypto/tink-go/v2/tink"
)

const (
	awsPrefix      = "aws-kms://"
	defaultTimeout = 5 * time.Second
)

// awsClient is a wrapper around an AWS SDK provided KMS client that can
// instantiate Tink primitives.
type awsClient struct {
	keyURIPrefix          string
	kms                   KMSAPI
	encryptionContextName EncryptionContextName
	timeout               time.Duration
	loadOpts              []func(*config.LoadOptions) error
	kmsOpts               []func(options *kms.Options)
}

// ClientOption is an interface for defining options that are passed to
// [NewClientWithOptions].
type ClientOption interface{ set(*awsClient) error }

type option func(*awsClient) error

func (o option) set(a *awsClient) error { return o(a) }

// WithKMS sets the underlying AWS KMS client to kms, a preexisting AWS KMS
// client instance.
//
// It's the callers responsibility to ensure that the configured region of kms
// aligns with the region in key URIs passed to this client. Otherwise, API
// requests will fail.
func WithKMS(kms KMSAPI) ClientOption {
	return option(func(a *awsClient) error {
		if a.kms != nil {
			return errors.New("WithKMS option cannot be used, KMS client already set")
		}
		a.kms = kms
		return nil
	})
}

// WithAPITimeout sets the timeout for API requests made by the KMS client.
func WithAPITimeout(timeout time.Duration) ClientOption {
	return option(func(a *awsClient) error {
		a.timeout = timeout
		return nil
	})
}

// WithAWSLoadOptions sets the load options used to create the AWS SDK config.
func WithAWSLoadOptions(loadOpts ...func(*config.LoadOptions) error) ClientOption {
	return option(func(a *awsClient) error {
		a.loadOpts = loadOpts
		return nil
	})
}

// WithKMSOptions sets the options used to create the AWS SDK KMS client.
func WithKMSOptions(kmsOpts ...func(options *kms.Options)) ClientOption {
	return option(func(a *awsClient) error {
		a.kmsOpts = kmsOpts
		return nil
	})
}

// EncryptionContextName specifies the name used in the EncryptionContext field
// of EncryptInput and DecryptInput requests. See [WithEncryptionContextName]
// for further details.
type EncryptionContextName uint

const (
	// AssociatedData will set the EncryptionContext name to "associatedData".
	AssociatedData EncryptionContextName = 1 + iota
	// LegacyAdditionalData will set the EncryptionContext name to "additionalData".
	LegacyAdditionalData
)

var encryptionContextNames = map[EncryptionContextName]string{
	AssociatedData:       "associatedData",
	LegacyAdditionalData: "additionalData",
}

func (n EncryptionContextName) valid() bool {
	_, ok := encryptionContextNames[n]
	return ok
}

func (n EncryptionContextName) String() string {
	if !n.valid() {
		return "unrecognized value " + strconv.Itoa(int(n))
	}
	return encryptionContextNames[n]
}

// WithEncryptionContextName sets the name which maps to the base64 encoded
// associated data within the EncryptionContext field of EncrypInput and
// DecryptInput requests.
//
// The default is [AssociatedData], which is compatible with the Tink AWS KMS
// extensions in other languages. In older versions of this packge, before this
// option was present, "additionalData" was hardcoded.
//
// This option is provided to facilitate compatibility with older ciphertexts.
func WithEncryptionContextName(name EncryptionContextName) ClientOption {
	return option(func(a *awsClient) error {
		if !name.valid() {
			return fmt.Errorf("invalid EncryptionContextName: %v", name)
		}
		if a.encryptionContextName != 0 {
			return errors.New("encryptionContextName already set")
		}
		a.encryptionContextName = name
		return nil
	})
}

// NewClientWithOptions returns a [registry.KMSClient] which wraps an AWS KMS
// client and will handle keys whose URIs start with uriPrefix.
//
// By default, the client will use default credentials.
//
// AEAD primitives produced by this client will use [AssociatedData] when
// serializing associated data.
func NewClientWithOptions(uriPrefix string, opts ...ClientOption) (registry.KMSClient, error) {
	if !strings.HasPrefix(strings.ToLower(uriPrefix), awsPrefix) {
		return nil, fmt.Errorf("uriPrefix must start with %q, but got %q", awsPrefix, uriPrefix)
	}

	a := &awsClient{
		keyURIPrefix: uriPrefix,
		timeout:      defaultTimeout,
	}

	for _, opt := range opts {
		if err := opt.set(a); err != nil {
			return nil, fmt.Errorf("failed setting option: %v", err)
		}
	}

	if a.kms == nil {
		k, err := buildKMSClient(a.timeout, a.loadOpts, a.kmsOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create KMS client: %w", err)
		}
		a.kms = k
	}

	if a.encryptionContextName == 0 {
		a.encryptionContextName = AssociatedData
	}

	return a, nil
}

// Supported returns true if keyURI starts with the URI prefix provided when
// creating the client.
func (c *awsClient) Supported(keyURI string) bool {
	return strings.HasPrefix(keyURI, c.keyURIPrefix)
}

// GetAEAD returns an implementation of the AEAD interface which performs
// cryptographic operations remotely via AWS KMS using keyURI.
//
// keyUri must be supported by this client and must have the following format:
//
//	aws-kms://arn:<partition>:kms:<region>:<path>
//
// See https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html
func (c *awsClient) GetAEAD(keyURI string) (tink.AEAD, error) {
	if !c.Supported(keyURI) {
		return nil, fmt.Errorf("keyURI must start with prefix %s, but got %s", c.keyURIPrefix, keyURI)
	}

	uri := strings.TrimPrefix(keyURI, awsPrefix)
	return newAWSAEAD(uri, c.kms, c.encryptionContextName, c.timeout), nil
}

func buildKMSClient(timeout time.Duration, loadOpts []func(*config.LoadOptions) error, kmsOpts []func(options *kms.Options)) (*kms.Client, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS default config: %w", err)
	}

	return kms.NewFromConfig(cfg, kmsOpts...), nil
}

type KMSAPI interface {
	Encrypt(ctx context.Context, params *kms.EncryptInput, optFns ...func(*kms.Options)) (*kms.EncryptOutput, error)
	Decrypt(ctx context.Context, params *kms.DecryptInput, optFns ...func(*kms.Options)) (*kms.DecryptOutput, error)
}
