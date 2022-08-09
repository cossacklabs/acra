//go:build !kms_aws_off
// +build !kms_aws_off

package kms

import (
	"github.com/cossacklabs/acra/keystore/kms"
	"github.com/cossacklabs/acra/keystore/kms/aws"
)

func init() {
	kms.RegisterKeyManagerCreator(TypeAWS, aws.NewKeyManager)
}
