/*
 * Copyright (c) 2018 Cossack Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import "AcraStruct.h"

/**
 * @file AcraWriter/AcraWriter.h
 * @brief AcraWriter generates AcraStructs, specially encrypted data, from provided plaintext.
 * @discussion AcraStruct encrypts data using mix of symmetric and asymmetric encryption,
 * using Themis Secure Cell and Themis Secure Message. Data is encrypted with publicKey,
 * that represents AcraStorage public key (known as <client_id>_storage.pub) or
 * with AcraZonePublicKeys (known as <zone_id>_zone.pub).
 * @see What is AcraWriter and how it works https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter
 * @see What is Zone https://github.com/cossacklabs/acra/wiki/Zones
 */
@interface AcraWriter : NSObject

/**
 * @brief Possible error codes when creating AcraStruct.
 */
typedef NS_ENUM(NSUInteger, AcraWriterError) {
  AcraWriterErrorEmptyData = 700,
  AcraWriterErrorWrongPublicKey = 701,
  AcraWriterErrorCantGenerateKeyPair = 702,
  AcraWriterErrorCantGenerateRandomKey = 703,
  AcraWriterErrorCantEncryptRandomKey = 704,
  AcraWriterErrorCantEncryptPayload = 705
};

/**
 * @discussion Method to generate AcraStruct from plain text message. Two option are possible: without Zones or with Zones.
 * Without zones: `publicKey` is AcraStorage public key.
 * With zones: `zoneID` is required, `publicKey` is Zone public key.
 * @param [in] message plaintext data to encrypt into AcraStruct.
 * @param [in] publicKey either storage key or zone key, depending if client wants to use Zones.
 * @param [in] zoneID is optional, when client is using Zones. If zoneId is represented as string Id, expected input is [@"some zone id here" dataUsingEncoding:NSUTF8StringEncoding]
 * @param [in] error is optional, pointer to Error on failure
 * @return data encrypted into AcraStruct format, or nil on error
 */
- (nullable AcraStruct *)createAcraStructFrom:(nonnull NSData *)message publicKey:(nonnull NSData *)publicKey zoneID:(nullable NSData *)zoneID error:(NSError * __autoreleasing *)error;

@end
