//go:build !kms_aws_off
// +build !kms_aws_off

package kms

import (
	"github.com/cossacklabs/acra/keystore/kms/aws"
	"github.com/cossacklabs/acra/keystore/kms/base"
)

func init() {
	base.RegisterKeyManagerCreator(TypeAWS, aws.NewKeyManager)
}
