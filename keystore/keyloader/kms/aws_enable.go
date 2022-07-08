//go:build !kmw_aws_off
// +build !kmw_aws_off

package kms

import (
	"github.com/cossacklabs/acra/keystore/kms"
	"github.com/cossacklabs/acra/keystore/kms/aws"
)

func init() {
	kms.RegisterEncryptorCreator(aws.KeyIdentifierPrefix, aws.NewEncryptor)
}
