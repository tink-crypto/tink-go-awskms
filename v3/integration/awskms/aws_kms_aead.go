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

// Package awskms provides integration with the [AWS KMS].
//
// [AWS KMS]: https://docs.aws.amazon.com/kms/latest/developerguide/kms-overview.html
package awskms

import (
	"context"
	"encoding/hex"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tink-crypto/tink-go/v2/tink"
)

// awsAEAD is an implementation of the AEAD interface which performs
// cryptographic operations remotely via the AWS KMS service using a specific
// key ID.
type awsAEAD struct {
	keyID                 string
	kms                   KMSAPI
	encryptionContextName EncryptionContextName
}

// NewAEADWithContext returns a new AEADWithContext instance. The opts are the same as those
// passed to NewClientWithOptions.
func NewAEADWithContext(ctx context.Context, keyID string, opts ...ClientOption) (tink.AEADWithContext, error) {
	keyURI := awsPrefix + keyID
	awsClient, err := newAWSClient(ctx, keyURI, opts...)
	if err != nil {
		return nil, err
	}
	return newAWSAEAD(keyID, awsClient.kms, awsClient.encryptionContextName), nil
}

// newAWSAEAD returns a new awsAEAD instance.
//
// keyID must have the following format:
//
//	arn:<partition>:kms:<region>:[<path>]
//
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newAWSAEAD(keyID string, kms KMSAPI, name EncryptionContextName) *awsAEAD {
	return &awsAEAD{
		keyID:                 keyID,
		kms:                   kms,
		encryptionContextName: name,
	}
}

// EncryptWithContext encrypts the plaintext with associatedData.
func (a *awsAEAD) EncryptWithContext(ctx context.Context, plaintext, associatedData []byte) ([]byte, error) {
	req := &kms.EncryptInput{
		KeyId:     aws.String(a.keyID),
		Plaintext: plaintext,
	}
	if len(associatedData) > 0 {
		ad := hex.EncodeToString(associatedData)
		req.EncryptionContext = map[string]string{a.encryptionContextName.String(): ad}
	}
	resp, err := a.kms.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.CiphertextBlob, nil
}

func (a *awsAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	return a.EncryptWithContext(context.TODO(), plaintext, associatedData)
}

// DecryptWithContext decrypts the ciphertext and verifies the associated data.
func (a *awsAEAD) DecryptWithContext(ctx context.Context, ciphertext, associatedData []byte) ([]byte, error) {
	req := &kms.DecryptInput{
		KeyId:          aws.String(a.keyID),
		CiphertextBlob: ciphertext,
	}
	if len(associatedData) > 0 {
		ad := hex.EncodeToString(associatedData)
		req.EncryptionContext = map[string]string{a.encryptionContextName.String(): ad}
	}
	resp, err := a.kms.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (a *awsAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	return a.DecryptWithContext(context.TODO(), ciphertext, associatedData)
}
