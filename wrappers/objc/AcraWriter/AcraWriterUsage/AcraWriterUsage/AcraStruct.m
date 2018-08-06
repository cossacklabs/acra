//
//  AcraStruct.m
//  AcraWriterUsage
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import "AcraStruct.h"

@interface AcraStruct()

@property (nonatomic, strong, nonnull) NSData * data;

@end

@implementation AcraStruct

- (instancetype)initWithData:(nonnull NSData *)data {
  self = [super init];
  if (self) {
    self.data = data;
  }
  return self;
}

@end
