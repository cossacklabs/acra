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

/**
 * @file AcraStruct/AcraStruct.h
 * @brief AcraStruct represents binary format of encrypted data.
 * @see What is AcraStruct inner structure https://github.com/cossacklabs/acra/wiki/AcraStruct
 */
@interface AcraStruct : NSObject

/**
 * @brief binary data of AcraStruct
*/
@property (nonatomic, readonly, nonnull) NSData * data;

@end
