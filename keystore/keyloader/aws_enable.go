//go:build !kms_aws_off
// +build !kms_aws_off

package keyloader

import (
	"github.com/cossacklabs/acra/keystore/keyloader/kms"
	"github.com/cossacklabs/acra/keystore/kms/aws"
	"github.com/cossacklabs/acra/keystore/kms/base"
)

func init() {
	base.RegisterKeyManagerCreator(kms.TypeAWS, aws.NewKeyManager)
}
