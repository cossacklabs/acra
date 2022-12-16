package kms

import (
	"testing"

	"github.com/cossacklabs/acra/keystore"
	"github.com/stretchr/testify/assert"
)

func TestKMSPerClientKeyMapper(t *testing.T) {
	keyMapper := NewKMSPerClientKeyMapper()

	t.Run("map with empty purpose in context", func(t *testing.T) {
		_, err := keyMapper.GetKeyID(keystore.KeyContext{})
		assert.NotNil(t, err)
		assert.Equal(t, ErrMissingKeyPurpose, err)
	})

	t.Run("map client related keys with empty clientID", func(t *testing.T) {
		_, err := keyMapper.GetKeyID(keystore.KeyContext{
			Purpose: keystore.PurposeStorageClientSymmetricKey,
		})

		assert.NotNil(t, err)
		assert.Equal(t, ErrEmptyClientIDProvided, err)
	})

	t.Run("map client related keys", func(t *testing.T) {
		clientID := "test_client_id"
		res, err := keyMapper.GetKeyID(keystore.KeyContext{
			Purpose:  keystore.PurposeStorageClientSymmetricKey,
			ClientID: []byte(clientID),
		})

		assert.Nil(t, err)
		assert.Equal(t, "acra_"+clientID, string(res))
	})

	t.Run("map poison record related keys", func(t *testing.T) {
		res, err := keyMapper.GetKeyID(keystore.KeyContext{
			Purpose: keystore.PurposePoisonRecordSymmetricKey,
		})

		assert.Nil(t, err)
		assert.Equal(t, "acra_poison", string(res))
	})

	t.Run("map audit-log keys", func(t *testing.T) {
		res, err := keyMapper.GetKeyID(keystore.KeyContext{
			Purpose: keystore.PurposeAuditLog,
		})

		assert.Nil(t, err)
		assert.Equal(t, "acra_audit_log", string(res))
	})

	t.Run("map unsupported keys purpose", func(t *testing.T) {
		_, err := keyMapper.GetKeyID(keystore.KeyContext{
			Purpose: "unsupported",
		})

		assert.NotNil(t, err)
		assert.Equal(t, ErrUnsupportedKeyPurpose, err)
	})
}
