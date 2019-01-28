//
//  AppDelegate.m
//  AcraWriterUsage
//
//  Created by Anastasiia on 8/2/18.
//  Copyright © 2018 Cossack Labs. All rights reserved.
//

#import "AppDelegate.h"
#import "AcraWriter/AcraWriter.h"

// if ONLY_LOCAL_SETUP is true, don't send AcraStruct to AcraServer,
// let users try project locally without being pissed off because of connection error
#define ONLY_LOCAL_SETUP 0

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
  
  [self generateAndSendAcraStruct];
  
  [self generateAndSendAcraStructWithZone];
  
  return YES;
}

- (void)generateAndSendAcraStruct {
  NSLog(@"Generating simple AcraStruct");
  
  // Generate storage keys, AcraWriter is using <client_id>_storage.pub public key
  // https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
  
  AcraWriter * aw = [AcraWriter new];
  NSString * acraStoragePublicKey = @"VUVDMgAAAC19EoDCAjPFi89Z/Y4bLX9FAzVonJ+Z1GmxKJQo/DvJY8K8nw9V";
  NSData * acraStoragePublicKeyData = [[NSData alloc] initWithBase64EncodedString:acraStoragePublicKey
                                                                          options:NSDataBase64DecodingIgnoreUnknownCharacters];
  
  NSError * generationError;
  AcraStruct * acraStruct = [aw createAcraStructFrom:[@"secret message" dataUsingEncoding:NSUTF8StringEncoding]
                                           publicKey:acraStoragePublicKeyData
                                              zoneID:nil
                                               error:&generationError];
  if (generationError) {
    NSLog(@"Error occurred while generating AcraStruct: %@", generationError);
  }
  
  if (ONLY_LOCAL_SETUP == 0) {
    [self sendAcraStruct:acraStruct zoneID:nil];
  } else {
    NSLog(@"simple AcraStruct %@", [acraStruct.data base64EncodedDataWithOptions:0]);
  }
}


- (void)generateAndSendAcraStructWithZone {
  NSLog(@"Generating simple AcraStruct with Zone");
  
  // Generate Zone keys, AcraWriter is using <zone_id>_zone.pub public key
  // https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
  
  AcraWriter * aw = [AcraWriter new];
  NSString * zonePublicKey = @"VUVDMgAAAC1dStsgAwKbjEzpd3Xptt+hjhFX3Kypbd36qjCF0koFzZHBNPLM";
  NSData * zonePublicKeyData = [[NSData alloc] initWithBase64EncodedString:zonePublicKey
                                                                   options:NSDataBase64DecodingIgnoreUnknownCharacters];
  NSString * zoneID = @"DDDDDDDDNVGIGGzYSCklWQPx";
  NSError * generationError;
  
  AcraStruct * acraStructWithZone = [aw createAcraStructFrom:[@"secret message with zones" dataUsingEncoding:NSUTF8StringEncoding]
                                                   publicKey:zonePublicKeyData
                                                      zoneID:[zoneID dataUsingEncoding:NSUTF8StringEncoding]
                                                       error:&generationError];
  if (generationError) {
    NSLog(@"Error occurred while generating AcraStruct with Zone: %@", generationError);
  }

  if (ONLY_LOCAL_SETUP == 0) {
    [self sendAcraStruct:acraStructWithZone zoneID:zoneID];
  } else {
    NSLog(@"AcraStruct with zone %@", [acraStructWithZone.data base64EncodedDataWithOptions:0]);
  }
}


- (void)sendAcraStruct:(AcraStruct *)acraStruct zoneID:(NSString *)zoneID {
  NSString * requestURL = [NSString stringWithFormat:@"http://127.0.0.1:8000/v1/decrypt"];
  if (zoneID != nil) {
    requestURL = [requestURL stringByAppendingString:[NSString stringWithFormat:@"?zone_id=%@", zoneID]];
  }
  NSURL *url = [NSURL URLWithString: requestURL];
  NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
  
  [request setURL:url];
  [request setHTTPMethod:@"POST"];
  [request setValue:@"application/octet-stream" forHTTPHeaderField:@"Content-Type"];
  [request setHTTPBody:acraStruct.data];
  
  NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration defaultSessionConfiguration]
                                                        delegate:self delegateQueue:nil];

  NSURLSessionDataTask *uploadTask = [session dataTaskWithRequest:request completionHandler:^(NSData * _Nullable data, NSURLResponse * _Nullable response, NSError * _Nullable error) {
    if (error) {
      NSLog(@"Got error: %@", error);
    }
    if (response) {
      NSLog(@"Got response code: %li", (long)((NSHTTPURLResponse *)response).statusCode);
    }
    if (data) {
      NSLog(@"Got decrypted data: %@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
    }
  }];
  [uploadTask setTaskDescription:(zoneID == nil) ? @"no zones" : @"with zones"];
  [uploadTask resume];
}

@end
