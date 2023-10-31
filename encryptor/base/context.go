package base

import (
	"context"

	"github.com/cossacklabs/acra/encryptor/base/config"
)

type settingKey struct{}

// NewContextWithEncryptionSetting makes a new context containing column encryption settings.
func NewContextWithEncryptionSetting(ctx context.Context, setting config.ColumnEncryptionSetting) context.Context {
	return context.WithValue(ctx, settingKey{}, setting)
}

// EncryptionSettingFromContext extracts column encryption settings for a context,
// or returns "nil" if there the context does not contain it.
func EncryptionSettingFromContext(ctx context.Context) (config.ColumnEncryptionSetting, bool) {
	// Explicitly check for presence and return explicit "nil" value
	// so that returned interface is "== nil".
	value := ctx.Value(settingKey{})
	if value == nil {
		return nil, false
	}
	setting, ok := value.(config.ColumnEncryptionSetting)
	return setting, ok
}
