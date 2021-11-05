/*
Copyright 2020, Cossack Labs Limited

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package storage

import (
	"time"

	"github.com/boltdb/bolt"
	"github.com/cossacklabs/acra/pseudonymization/common"
)

type boltdbStorage struct {
	db *bolt.DB

	accessGranularity time.Duration
}

// NewBoltDBTokenStorage return token storage using boltDB
func NewBoltDBTokenStorage(db *bolt.DB) common.TokenStorage {
	return &boltdbStorage{db, common.DefaultAccessTimeGranularity}
}

var tokenBucket = []byte("tokens")

// Save data with defined id and context
func (b *boltdbStorage) Save(id []byte, context common.TokenContext, data []byte) error {
	ctx := common.AggregateTokenContextToBytes(context)
	return b.db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(tokenBucket)
		if err != nil {
			return err
		}

		ctxBucket, err := bucket.CreateBucketIfNotExists(ctx)
		if err != nil {
			return err
		}
		if ctxBucket.Get(id) != nil {
			return common.ErrTokenExists
		}
		value := common.EmbedMetadata(data, common.NewTokenMetadata())
		return ctxBucket.Put(id, value)
	})
}

// Get data with defined id and context
func (b *boltdbStorage) Get(id []byte, context common.TokenContext) ([]byte, error) {
	var value []byte
	var updatedMetadata []byte
	ctx := common.AggregateTokenContextToBytes(context)
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(tokenBucket)
		if bucket == nil {
			return common.ErrTokenNotFound
		}
		ctxBucket := bucket.Bucket(ctx)
		if ctxBucket == nil {
			return common.ErrTokenNotFound
		}
		encoded := ctxBucket.Get(id)
		if encoded == nil {
			return common.ErrTokenNotFound
		}
		data, metadata, err := common.ExtractMetadata(encoded)
		if err != nil {
			return err
		}
		// If the token is disabled, pretend that it's not there. (Don't update last access time either.)
		if metadata.Disabled {
			return common.ErrTokenDisabled
		}
		// Keep last access time updated, but don't update it more often than specified granularity.
		now := time.Now().UTC()
		if metadata.AccessedBefore(now, b.accessGranularity) {
			metadata.Accessed = now
			updatedMetadata = common.EmbedMetadata(data, metadata)
		}
		value = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	// If metadata update is needed, open a separate writeable transaction to perform it.
	if updatedMetadata != nil {
		err := b.db.Update(func(tx *bolt.Tx) error {
			bucket := tx.Bucket(tokenBucket)
			if bucket == nil {
				return common.ErrTokenNotFound
			}
			ctxBucket := bucket.Bucket(ctx)
			if ctxBucket == nil {
				return common.ErrTokenNotFound
			}
			return ctxBucket.Put(id, updatedMetadata)
		})
		if err != nil {
			return nil, err
		}
	}
	return value, nil
}

// Stat returns metadata of a token entry.
func (b *boltdbStorage) Stat(id []byte, context common.TokenContext) (common.TokenMetadata, error) {
	var metadata common.TokenMetadata
	ctx := common.AggregateTokenContextToBytes(context)
	err := b.db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(tokenBucket)
		if bucket == nil {
			return common.ErrTokenNotFound
		}
		ctxBucket := bucket.Bucket(ctx)
		if ctxBucket == nil {
			return common.ErrTokenNotFound
		}
		encoded := ctxBucket.Get(id)
		if encoded == nil {
			return common.ErrTokenNotFound
		}
		var err error
		_, metadata, err = common.ExtractMetadata(encoded)
		return err
	})
	return metadata, err
}

// SetAccessTimeGranularity sets access time granularity.
func (b *boltdbStorage) SetAccessTimeGranularity(granularity time.Duration) error {
	b.accessGranularity = granularity
	return nil
}

// Iterate over token metadata in the storage.
func (b *boltdbStorage) VisitMetadata(cb func(dataLength int, metadata common.TokenMetadata) (common.TokenAction, error)) error {
	err := b.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(tokenBucket)
		if bucket == nil {
			// Apparently, no tokens have even been saved into the storage if there is no root bucket.
			return nil
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			// Skip non-buckets. (There shouldn't be any, but just in case.)
			if v != nil {
				continue
			}
			ctxBucket := bucket.Bucket(k)
			err := b.visitBucket(ctxBucket, cb)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (b *boltdbStorage) visitBucket(ctxBucket *bolt.Bucket, cb func(dataLength int, metadata common.TokenMetadata) (common.TokenAction, error)) error {
	cursor := ctxBucket.Cursor()
	for id, v := cursor.First(); id != nil; id, v = cursor.Next() {
		// Skip buckets. (There shouldn't be any, but just in case.)
		if v == nil {
			continue
		}
		data, metadata, err := common.ExtractMetadata(v)
		if err != nil {
			return err
		}
		action, err := cb(len(data), metadata)
		if err != nil {
			return err
		}
		switch action {
		case common.TokenDisable:
			if !metadata.Disabled {
				metadata.Disabled = true
				value := common.EmbedMetadata(data, metadata)
				err := ctxBucket.Put(id, value)
				if err != nil {
					return err
				}
			}
		case common.TokenEnable:
			if metadata.Disabled {
				metadata.Disabled = false
				value := common.EmbedMetadata(data, metadata)
				err := ctxBucket.Put(id, value)
				if err != nil {
					return err
				}
			}
		case common.TokenRemove:
			err := ctxBucket.Delete(id)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
