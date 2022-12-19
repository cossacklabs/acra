//
//  AcraWriterUsageTests.m
//  AcraWriterUsageTests
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "AcraWriter/AcraWriter.h"
#import <objcthemis/objcthemis.h>
#import <objcthemis/smessage.h>

@interface AcraWriterUsageTests : XCTestCase

@end

@implementation AcraWriterUsageTests

- (void)testAcraWriterWrongKeys {
  
  NSMutableData *data = [NSMutableData dataWithLength:1000];
  int result = SecRandomCopyBytes(kSecRandomDefault, 1000, data.mutableBytes);
  if (result != 0) {
    return XCTFail(@"error while generating random data");
  }
  
  NSError * error;
  
  AcraStruct * as = [[AcraWriter new] createAcraStructFrom:data publicKey:nil
                                                    additionalContext:nil error:&error];
  XCTAssertNotNil(error, @"should throw error if empty public key");
  XCTAssertTrue(error.code == AcraWriterErrorWrongPublicKey, @"error code should be correct");
  XCTAssertNil(as, @"AcraStruct should not be created");
  
  as = [[AcraWriter new] createAcraStructFrom:data publicKey:[@"wrong public key" dataUsingEncoding:NSUTF8StringEncoding]
                                  additionalContext:nil error:&error];
  XCTAssertNotNil(error, @"should throw error if wrong public key");
  XCTAssertTrue(error.code == AcraWriterErrorCantEncryptRandomKey, @"error code should be correct");
  XCTAssertNil(as, @"AcraStruct should not be created");
  
  error = nil;
  NSData * pubKey = [[NSData alloc] initWithBase64EncodedString:@"VUVDMgAAAC26myz0A0MBRd1y1Pm24W0mMWwT4cWW4jTATXIr7E7kbL//EGhy"
                                                        options:NSDataBase64DecodingIgnoreUnknownCharacters];
  as = [[AcraWriter new] createAcraStructFrom:data publicKey:pubKey
                                       additionalContext:nil error:&error];
  XCTAssertNil(error, @"should NOT throw error if correct public key");
  XCTAssertNotNil(as, @"AcraStruct should be created");
  XCTAssertNotNil(as.data, @"AcraStruct binary data should be created");
  
}

- (void)testAcraWriterWrongData {
  NSData * pubKey = [[NSData alloc] initWithBase64EncodedString:@"VUVDMgAAAC26myz0A0MBRd1y1Pm24W0mMWwT4cWW4jTATXIr7E7kbL//EGhy"
                                                        options:NSDataBase64DecodingIgnoreUnknownCharacters];
  
  NSError * error;
  AcraStruct * as = [[AcraWriter new] createAcraStructFrom:nil publicKey:pubKey
                                                    additionalContext:nil error:&error];
  XCTAssertNotNil(error, @"should throw error if empty data");
  XCTAssertTrue(error.code == AcraWriterErrorEmptyData, @"error code should be correct");
  XCTAssertNil(as, @"AcraStruct should not be created");
  
  error = nil;
  as = [[AcraWriter new] createAcraStructFrom:[NSData data] publicKey:pubKey
                                       additionalContext:nil error:&error];
  XCTAssertNotNil(error, @"should throw error if zero data");
  XCTAssertTrue(error.code == AcraWriterErrorEmptyData, @"error code should be correct");
  XCTAssertNil(as, @"AcraStruct should not be created");
}

- (void)testAcraStructStructure {
  [self createAcraStructAndCheckStructure:10];
  [self createAcraStructAndCheckStructure:600];
  [self createAcraStructAndCheckStructure:1000];
  [self createAcraStructAndCheckStructure:1024]; // 1 kB
  [self createAcraStructAndCheckStructure:1024 * 10]; // 10 kB
  [self createAcraStructAndCheckStructure:1024 * 1024]; // 1 MB
  [self createAcraStructAndCheckStructure:1024 * 1024 * 10]; // 10 MB
  [self createAcraStructAndCheckStructure:1024 * 1024 * 100]; // 100 MB
  [self createAcraStructAndCheckStructure:1024 * 1024 * 1024]; // 1 GB
}

- (void)createAcraStructAndCheckStructure:(NSUInteger)payloadLength {
  TSKeyGen * keygenEC = [[TSKeyGen alloc] initWithAlgorithm:TSKeyGenAsymmetricAlgorithmEC];
  
  NSLog(@"Testing AcraStruct with length %lu", (unsigned long)payloadLength);
  
  NSMutableData *data = [NSMutableData dataWithLength:payloadLength];
  int result = SecRandomCopyBytes(kSecRandomDefault, payloadLength, data.mutableBytes);
  if (result != 0 || data == nil) {
    return XCTFail(@"error while generating random data");
  }
  
  NSError * error;
  AcraStruct * as = [[AcraWriter new] createAcraStructFrom:data publicKey:keygenEC.publicKey
                                                    additionalContext:nil
                                                     error:&error];
  XCTAssertNil(error, @"should NOT throw error if correct public key");
  XCTAssertNotNil(as, @"AcraStruct should be created");
  XCTAssertNotNil(as.data, @"AcraStruct binary data should be created");
  
  NSLog(@"AcraStruct length %lu", (unsigned long)[as.data length]);
  
  
  // read header, 8 bytes of 34 (0x22)
  NSInteger startingByte = 0;
  NSInteger headerLength = 8;
  char header[headerLength];
  [as.data getBytes:header range:NSMakeRange(startingByte, headerLength)];
  for (int index = 0; index < headerLength; index++) {
    XCTAssertTrue(header[index] == 34, @"AcraStruct header has wrong structure");
  }
  startingByte += headerLength;
  
  // read inner public key, 45 bytes
  NSInteger publicKeyLength = 45;
  NSData * innerPublicKey = [as.data subdataWithRange:NSMakeRange(startingByte, publicKeyLength)];
  XCTAssertNotNil(innerPublicKey, @"innerPublicKey should be read");
  startingByte += publicKeyLength;
  
  // create decryptor
  TSMessage * message = [[TSMessage alloc] initInEncryptModeWithPrivateKey:keygenEC.privateKey peerPublicKey:innerPublicKey];
  
  // read encrypted symmetric key, 84 bytes
  NSInteger encryptedSymmKeyLength = 84;
  NSData * encryptedSymmetricKey = [as.data subdataWithRange:NSMakeRange(startingByte, encryptedSymmKeyLength)];
  XCTAssertNotNil(encryptedSymmetricKey, @"encryptedSymmKey should be read");
  startingByte += encryptedSymmKeyLength;
  
  // decrypt symmetric key
  NSError * messageDecryptionError;
  NSData * symmKey = [message unwrapData:encryptedSymmetricKey error:&messageDecryptionError];
  XCTAssertNil(messageDecryptionError, @"should NOT throw decryption error");
  XCTAssertNotNil(symmKey, @"symmetric key should be decrypted");
  
  // create decryptor
  TSCellSeal * cell = [[TSCellSeal alloc] initWithKey:symmKey];
  
  // read length of data, 8 bytes, little endian
  UInt64 dataLength;
  NSUInteger dataLengthLength = sizeof(dataLength); // 8 bytes
  [as.data getBytes:&dataLength range:NSMakeRange(startingByte, dataLengthLength)];
  dataLength = CFSwapInt64LittleToHost(dataLength); // from little endian
  startingByte += dataLengthLength;
  
  NSLog(@"Encrypted data length %lu", (unsigned long)dataLength);
  
  // read payload data
  NSData * encryptedData = [as.data subdataWithRange:NSMakeRange(startingByte, dataLength)];
  XCTAssertNotNil(encryptedData, @"encryptedData should be read");
  
  // decrypt payload data
  NSError * dataDecryptionError;
  NSData * decryptedData = [cell unwrapData:encryptedData error:&dataDecryptionError];
  XCTAssertNil(dataDecryptionError, @"should NOT throw decryption error");
  XCTAssertNotNil(decryptedData, @"payload data should be decrypted");
  XCTAssertTrue(decryptedData.length == data.length, @"original and decrypted data length should be the same");
  XCTAssertTrue([decryptedData isEqualToData:data], @"original and decrypted data should be the same");
}

@end
