This example contains CLion project with AcraStruct generation with and without Zones.

# Building and running

Please run project from Acra repository using CLion and entry point `main.cpp`. Supports C++14 standard.

## Dependencies

1. This example uses AcraWriter C++ library (`acrawriter.hpp`), that we suggest to add to your project as source file into `lib` folder. 
AcraWriter C++ source code is located in the [`acra/wrappers/cpp`](https://github.com/cossacklabs/acra/tree/master/wrappers/cpp) folder, and linked as library in CMakeLists.txt.

2. AcraWriter depends on Themis system library and ThemisPP library. Themis and ThemisPP should be installed as system libraries and linked to the project.

Part of CMakeLists.txt file:

```
project(acrawriter_cpp)
set(CMAKE_CXX_STANDARD 14)

set(ACRAWRITER ../../wrappers/cpp)
include_directories(${ACRAWRITER})

set(LIBS libs)
include_directories(${LIBS})

set(
    SOURCE_FILES
    ${ACRAWRITER}/acrawriter.hpp
    ${LIBS}
    main.cpp
    )

add_executable(acrawriter_cpp ${SOURCE_FILES})
target_link_libraries(acrawriter_cpp themis crypto)
```

## Encoding and decoding

Acra and Themis works with binary data (`vector<uint8_t>`), but encryption keys are usually distributed as base64-encoded strings. We suggest using external library [cppcodec](https://github.com/tplgy/cppcodec) to decode base64 to binary. 

Decoding public key into `vector<uint8_t>`:

```cpp
vector<uint8_t> pub_key = base64::decode("VUVDMgAAAC1SGS5iAprH9f1sf7GR4OZ/J1YEn8lEwrgmI36G1JOnx7BITfK/");
```


# Generating AcraStruct without zone

Create AcraStructs from data-to-encrypt and Acra public storage key (don't forget to update key to your AcraServer's key):

```cpp
#include <cppcodec/base64_rfc4648.hpp>

#include "acrawriter.hpp"

using acra = acrawriter::acrawriter;
using base64 = cppcodec::base64_rfc4648;
using namespace std;

static string message("secret message");
acra::data message_vector(message.c_str(), message.c_str() + message.length());

vector<uint8_t> pub_key = base64::decode("VUVDMgAAAC1SGS5iAprH9f1sf7GR4OZ/J1YEn8lEwrgmI36G1JOnx7BITfK/");

// init acrawriter
acra acrawriter;

// create acrastruct
acra::acrastruct as = acrawriter.create_acrastruct(message_vector, pub_key);
```


# Generating AcraStruct with zone

Create AcraStructs from data-to-encrypt, ZoneID and Acra public zone key (don't forget to update key to your AcraServer's key):

```cpp
#include <cppcodec/base64_rfc4648.hpp>

#include "acrawriter.hpp"

using acra = acrawriter::acrawriter;
using base64 = cppcodec::base64_rfc4648;
using namespace std;

static string message("secret message");
acra::data message_vector(message.c_str(), message.c_str() + message.length());

static string zone_id("DDDDDDDDvTOInNRROHOihRkf");
acra::data zone_id_vector(zone_id.c_str(), zone_id.c_str() + zone_id.length());

vector<uint8_t> zone_pub_key = base64::decode("VUVDMgAAAC1GQ4j5AgEwz22ion8C0lvwRGJSjaC/G6ver3oOqmbBrIBjpdRo");

// init acrawriter
acra acrawriter;

// create acrastruct
acra::acrastruct as_with_zone = acrawriter.create_acrastruct(message_with_zone_vector, zone_pub_key, zone_id_vector);
```

# Installing Themis system library

AcraWriter C++ uses cryptographic library Themis and ThemisPP (C++ wrapper) as cryptographic core. Depending on your OS, you have different options to install Themis parts: via package manager, from package repository, from code source.

Please see exact instructions in the [Themis C++ installation guide](https://github.com/cossacklabs/themis/wiki/CPP-Howto).
