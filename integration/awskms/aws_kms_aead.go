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
	"encoding/hex"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/kms/kmsiface"
)

// AWSAEAD is an implementation of the AEAD interface which performs
// cryptographic operations remotely via the AWS KMS service using a specific
// key ID.
type AWSAEAD struct {
	keyID                 string
	kms                   kmsiface.KMSAPI
	encryptionContextName EncryptionContextName
}

// newAWSAEAD returns a new AWSAEAD instance.
//
// keyID must have the following format:
//
//	arn:<partition>:kms:<region>:[<path>]
//
// See http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html.
func newAWSAEAD(keyID string, kms kmsiface.KMSAPI, name EncryptionContextName) *AWSAEAD {
	return &AWSAEAD{
		keyID:                 keyID,
		kms:                   kms,
		encryptionContextName: name,
	}
}

// Encrypt encrypts the plaintext with associatedData.
func (a *AWSAEAD) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	req := &kms.EncryptInput{
		KeyId:     aws.String(a.keyID),
		Plaintext: plaintext,
	}
	if len(associatedData) > 0 {
		ad := hex.EncodeToString(associatedData)
		req.EncryptionContext = map[string]*string{a.encryptionContextName.String(): &ad}
	}
	resp, err := a.kms.Encrypt(req)
	if err != nil {
		return nil, err
	}
	return resp.CiphertextBlob, nil
}

// Decrypt decrypts the ciphertext and verifies the associated data.
func (a *AWSAEAD) Decrypt(ciphertext, associatedData []byte) ([]byte, error) {
	req := &kms.DecryptInput{
		KeyId:          aws.String(a.keyID),
		CiphertextBlob: ciphertext,
	}
	if len(associatedData) > 0 {
		ad := hex.EncodeToString(associatedData)
		req.EncryptionContext = map[string]*string{a.encryptionContextName.String(): &ad}
	}
	resp, err := a.kms.Decrypt(req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
