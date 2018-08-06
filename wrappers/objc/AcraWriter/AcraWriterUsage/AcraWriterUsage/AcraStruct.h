//
//  AcraStruct.h
//  AcraWriterUsage
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AcraStruct : NSObject

@property (nonatomic, readonly, nonnull) NSData * data;

- (instancetype)initWithData:(nonnull NSData *)data;

@end
