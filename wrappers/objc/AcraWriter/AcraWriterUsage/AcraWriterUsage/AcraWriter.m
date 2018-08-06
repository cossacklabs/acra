//
//  AcraWriter.m
//  AcraWriterUsage
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import <CoreFoundation/CoreFoundation.h>
#import "AcraWriter.h"
#import <objcthemis/objcthemis.h>


@implementation AcraWriter

static NSString *kErrorDomain = @"com.CossackLabs.Acra.Error";
static NSUInteger kErrorCodeNoKeys = 100;

static NSUInteger kSymmetricKeySize = 32;
static NSUInteger kAcraStructHeaderByte = 34;

- (nullable AcraStruct *)createAcraStructFrom:(NSData *)message publicKey:(NSData *)publicKey zoneID:(nullable NSData *)zoneID error:(NSError * __autoreleasing *)error {
  
  // 1. generate EC keypair
  TSKeyGen * keygenEC = [[TSKeyGen alloc] initWithAlgorithm:TSKeyGenAsymmetricAlgorithmEC];
  
  if (!keygenEC) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:kErrorCodeNoKeys
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't generate EC keypair, check Themis installation in dependencies"}];
    return nil;
  }
  
  // 2. generate random symm key with @(kSymmetricKeySize) size
  NSMutableData *symmetricKey = [NSMutableData dataWithLength:kSymmetricKeySize];
  int result = SecRandomCopyBytes(kSecRandomDefault, kSymmetricKeySize, symmetricKey.mutableBytes);
  if (result != 0) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:kErrorCodeNoKeys
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't generate random symmetric key for encrypting data"}];
    return nil;
  }
  
  // 3. encrypt random symmetric key using asymmetric encryption with random private key and acra/zone public key
  TSMessage * asymetricEncrypter = [[TSMessage alloc] initInEncryptModeWithPrivateKey:keygenEC.privateKey peerPublicKey:publicKey];
  NSData * encryptedRandomSymmKey = [asymetricEncrypter wrapData:symmetricKey
                                                           error:error];
  if (*error) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:kErrorCodeNoKeys
                             userInfo:@{ NSLocalizedDescriptionKey : @"Can't encrypt symmetric key: check if AcraPublicKeys is valid"}];
    return nil;
  }
  
  // 4. encrypt payload using symmetric encryption and random symm key
  TSCellSeal * symmetricEncrypter = [[TSCellSeal alloc] initWithKey:symmetricKey];
  NSData * encryptedMessage = [symmetricEncrypter wrapData:message context:zoneID error:error];
  if (*error) {
    *error = [NSError errorWithDomain:kErrorDomain
                                 code:kErrorCodeNoKeys
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
