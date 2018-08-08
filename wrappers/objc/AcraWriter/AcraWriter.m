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

#import "AcraWriter.h"
#import "AcraStruct+Internal.h"
#import <objcthemis/objcthemis.h>

@implementation AcraWriter

static NSString *kErrorDomain = @"com.CossackLabs.Acra.Error";
static NSUInteger kSymmetricKeySize = 32;
static NSUInteger kAcraStructHeaderByte = 34;

- (nullable AcraStruct *)createAcraStructFrom:(nonnull NSData *)message publicKey:(nonnull NSData *)publicKey zoneID:(nullable NSData *)zoneID error:(NSError * __autoreleasing *)error {
  
  if (message == nil || [message length] == 0) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:AcraWriterErrorEmptyData
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't encrypt empty payload"}];
    return nil;
  }
  
  if (publicKey == nil) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:AcraWriterErrorWrongPublicKey
                             userInfo:@{ NSLocalizedDescriptionKey : @"Public key is empty or wrong"}];
    return nil;
  }
  
  // 1. generate EC keypair
  TSKeyGen * keygenEC = [[TSKeyGen alloc] initWithAlgorithm:TSKeyGenAsymmetricAlgorithmEC];
  
  if (!keygenEC) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:AcraWriterErrorCantGenerateKeyPair
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't generate EC keypair, check Themis installation in dependencies"}];
    return nil;
  }
  
  // 2. generate random symm key with @(kSymmetricKeySize) size
  NSMutableData *symmetricKey = [NSMutableData dataWithLength:kSymmetricKeySize];
  int result = SecRandomCopyBytes(kSecRandomDefault, kSymmetricKeySize, symmetricKey.mutableBytes);
  if (result != 0) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:AcraWriterErrorCantGenerateRandomKey
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't generate random symmetric key for encrypting data"}];
    return nil;
  }
  
  // 3. encrypt random symmetric key using asymmetric encryption with random private key and acra/zone public key
  TSMessage * asymetricEncrypter = [[TSMessage alloc] initInEncryptModeWithPrivateKey:keygenEC.privateKey peerPublicKey:publicKey];
  NSData * encryptedRandomSymmKey = [asymetricEncrypter wrapData:symmetricKey
                                                           error:error];
  if (*error) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:AcraWriterErrorCantEncryptRandomKey
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't encrypt symmetric key: check if PublicKey is valid"}];
    return nil;
  }
  
  // 4. encrypt payload using symmetric encryption and random symm key
  TSCellSeal * symmetricEncrypter = [[TSCellSeal alloc] initWithKey:symmetricKey];
  NSData * encryptedMessage = [symmetricEncrypter wrapData:message context:zoneID error:error];
  if (*error) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:AcraWriterErrorCantEncryptPayload
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't encrypt payload"}];
    return nil;
  }
  
  // convert encrypted data length to little endian
  uint64_t encryptedMessageLength = CFSwapInt64HostToLittle(encryptedMessage.length);
  
  // zeroing symm key
  [symmetricKey resetBytesInRange:NSMakeRange(0, [symmetricKey length])];
  
  // 5. pack acrastruct
  
  // 34, 34, 34, 34, 34, 34, 34, 34
  UInt8 header[] = { kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte };
  NSMutableData * acraStructData = [NSMutableData new];
  [acraStructData appendBytes:(uint8_t*)header length:sizeof(header)];
  [acraStructData appendData:keygenEC.publicKey];
  [acraStructData appendData:encryptedRandomSymmKey];
  [acraStructData appendBytes:&encryptedMessageLength length:sizeof(encryptedMessageLength)];
  [acraStructData appendData:encryptedMessage];
  
  return [[AcraStruct alloc] initWithData:acraStructData];
}

@end
