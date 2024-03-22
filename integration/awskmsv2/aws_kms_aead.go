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

// Package awskmsv2 provides integration with the AWS Key Management Service.
package awskmsv2

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

// AWSAEAD is an implementation of the AEAD interface which performs
// cryptographic operations remotely via the AWS KMS service using a specific
// key URI.
type AWSAEAD struct {
	keyURI                string
	kms                   KMSAPI
	encryptionContextName EncryptionContextName
	timeout               time.Duration
}

// newAWSAEAD returns a new AWSAEAD instance.
//
// keyURI must have the following format:
//
//	aws-kms://arn:<partition>:kms:<region>:[<path>]
//
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newAWSAEAD(keyURI string, kms KMSAPI, name EncryptionContextName, timeout time.Duration) *AWSAEAD {
	return &AWSAEAD{
		keyURI:                keyURI,
		kms:                   kms,
		encryptionContextName: name,
		timeout:               timeout,
	}
}

// Encrypt encrypts the plaintext with associatedData.
func (a *AWSAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	req := &kms.EncryptInput{
		KeyId:     aws.String(a.keyURI),
		Plaintext: plaintext,
	}
	if len(associatedData) > 0 {
		ad := hex.EncodeToString(associatedData)
		req.EncryptionContext = map[string]string{a.encryptionContextName.String(): ad}
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	resp, err := a.kms.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.CiphertextBlob, nil
}

// Decrypt decrypts the ciphertext and verifies the associated data.
func (a *AWSAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	req := &kms.DecryptInput{
		KeyId:          aws.String(a.keyURI),
		CiphertextBlob: ciphertext,
	}
	if len(associatedData) > 0 {
		ad := hex.EncodeToString(associatedData)
		req.EncryptionContext = map[string]string{a.encryptionContextName.String(): ad}
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()
	resp, err := a.kms.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
