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

#ifndef AcraStruct_Internal_h
#define AcraStruct_Internal_h

/**
 * @file AcraStruct/AcraStruct+Internal.h
 * @brief Private initializer of AcraStruct.
 */
@interface AcraStruct ()

/**
 * @discussion Method initializer
 * @param [in] data packed data in correct AcraStruct structure.
 * @return AcraStruct
 */
- (instancetype)initWithData:(nonnull NSData *)data;

@end

#endif /* AcraStruct_Internal_h */
