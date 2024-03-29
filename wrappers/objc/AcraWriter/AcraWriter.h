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
 * that represents AcraStorage public key (known as <client_id>_storage.pub).
 * @see What is AcraWriter and how it works https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter
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
 * @discussion Method to generate AcraStruct from plain text message.
 * `publicKey` is AcraStorage public key.
 * @param [in] message plaintext data to encrypt into AcraStruct.
 * @param [in] publicKey either storage key.
 * @param [in] additionalContext is optional, may be used for AEAD encryption.
 * @param [in] error is optional, pointer to Error on failure
 * @return data encrypted into AcraStruct format, or nil on error
 */
- (nullable AcraStruct *)createAcraStructFrom:(nonnull NSData *)message publicKey:(nonnull NSData *)publicKey additionalContext:(nullable NSData *)additionalContext error:(NSError * __autoreleasing *)error;

@end
