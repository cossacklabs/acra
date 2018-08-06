//
//  AcraWriter.h
//  AcraWriterUsage
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "AcraStruct.h"

@interface AcraWriter : NSObject

- (nullable AcraStruct *)createAcraStructFrom:(NSData *)message publicKey:(NSData *)publicKey zoneID:(nullable NSData *)zoneID error:(NSError * __autoreleasing *)error;

@end
