//
//  AcraWriter.m
//  AcraWriter
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <objcthemis/objcthemis.h>

- (void)runExampleSecureCellSealMode {
  NSLog(@"----------------- %s -----------------", sel_getName(_cmd));
  
  NSData * masterKeyData = [self generateMasterKey];
  TSCellSeal * cellSeal = [[TSCellSeal alloc] initWithKey:masterKeyData];
  
  if (!cellSeal) {
    NSLog(@"%s Error occurred while initializing object cellSeal", sel_getName(_cmd));
    return;
  }
  
  NSString * message = @"All your base are belong to us!";
  NSString * context = @"For great justice";
  NSError * themisError;
  
  
  // context is optional parameter and may be ignored
  NSData * encryptedMessage = [cellSeal wrapData:[message dataUsingEncoding:NSUTF8StringEncoding]
                                         context:[context dataUsingEncoding:NSUTF8StringEncoding]
                                           error:&themisError];
  
  if (themisError) {
    NSLog(@"%s Error occurred while enrypting %@", sel_getName(_cmd), themisError);
    return;
  }
  NSLog(@"encryptedMessage = %@", encryptedMessage);
  
  NSData * decryptedMessage = [cellSeal unwrapData:encryptedMessage
                                           context:[context dataUsingEncoding:NSUTF8StringEncoding]
                                             error:&themisError];
  if (themisError) {
    NSLog(@"%s Error occurred while decrypting %@", sel_getName(_cmd), themisError);
    return;
  }
  NSString * resultString = [[NSString alloc] initWithData:decryptedMessage
                                                  encoding:NSUTF8StringEncoding];
  NSLog(@"%s resultString = %@", sel_getName(_cmd), resultString);
}
