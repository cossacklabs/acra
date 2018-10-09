#ifndef ACRA_ACRAWRITER_
#define ACRA_ACRAWRITER_

#include <vector>
#include <random>
#include <climits>
#include <algorithm>
#include <functional>
#include <iostream>

#include <themis/themis.h>
#include "themispp/secure_cell.hpp"
#include "themispp/secure_message.hpp"
#include "themispp/secure_keygen.hpp"
#include "themispp/secure_rand.hpp"

#include <cstdint>


//// https://github.com/steinwurf/endian/blob/master/src/endian/is_big_endian.hpp
namespace endian {
/// Checks if the platform is big- or little-endian.
///
/// From a test proposed here:
/// http://stackoverflow.com/questions/1001307/
///
/// @return True if the platform is big endian otherwise false.
    inline bool is_big_endian() {
      union {
          uint32_t i;
          uint8_t c[4];
      } test = {0x01020304};

      return test.c[0] == 1;
    }

//// https://github.com/tatewake/endian-template/blob/master/tEndian.h
    inline uint64_t swap_endian(uint64_t b) {
      uint64_t n;
      ((uint8_t *) &n)[0] = ((uint8_t *) &b)[7];
      ((uint8_t *) &n)[1] = ((uint8_t *) &b)[6];
      ((uint8_t *) &n)[2] = ((uint8_t *) &b)[5];
      ((uint8_t *) &n)[3] = ((uint8_t *) &b)[4];
      ((uint8_t *) &n)[4] = ((uint8_t *) &b)[3];
      ((uint8_t *) &n)[5] = ((uint8_t *) &b)[2];
      ((uint8_t *) &n)[6] = ((uint8_t *) &b)[1];
      ((uint8_t *) &n)[7] = ((uint8_t *) &b)[0];
      return n;
    }
}

namespace acrawriterpp {

    using namespace themispp;
    using namespace std;
    using namespace endian;

    class acrawriter_t {

    public:
        typedef vector<uint8_t> data_t;
        typedef vector<uint8_t> acrastruct_t;

//    const acrastruct_t& create_acra_struct(const data_t& message, const data_t& zone_public_key, const data_t& zone_id){
//      acrastruct_t acrastruct = {'h', 'e', 'l', 'l', 'o'};
//
//      return acrastruct;
//    }

        acrastruct_t create_acra_struct(const data_t &message, const data_t &public_key) {
          // 1. generate EC keypair
          secure_key_pair_generator_t<EC> key_pair_generator;
          data_t temp_private_key = key_pair_generator.get_priv();
          data_t temp_public_key = key_pair_generator.get_pub();

          // 2. generate random symm key with `symmetric_key_length` size
          using random_bytes_engine = independent_bits_engine<
              default_random_engine, CHAR_BIT, uint8_t>;
          random_bytes_engine rbe;
          vector<uint8_t> symmertic_key(symmetric_key_length);
          generate(begin(symmertic_key), end(symmertic_key), ref(rbe));

          // 3. encrypt random symmetric key using asymmetric encryption with random private key and acra/zone public key
          secure_message_t secure_message(temp_private_key, public_key);
          data_t encrypted_symm_key = secure_message.encrypt(symmertic_key);

          // 4. encrypt payload using symmetric encryption and random symm key
          secure_cell_seal_t secure_cell(symmertic_key);
          data_t encrypted_message = secure_cell.encrypt(message);

          // convert encrypted data length to little endian
          uint64_t em_length = encrypted_message.size();

//          if (is_big_endian()) {
//            em_length = swap_endian(em_length);
//          }

          // zeroing symm key

          // 5. pack acrastruct

          // header is ''''''''
          data_t header = {acrastruct_header_byte, acrastruct_header_byte, acrastruct_header_byte,
                           acrastruct_header_byte,
                           acrastruct_header_byte, acrastruct_header_byte, acrastruct_header_byte,
                           acrastruct_header_byte};

          acrastruct_t acrastruct;
          acrastruct.reserve(header.size() + temp_public_key.size() + encrypted_symm_key.size() + sizeof(em_length) + encrypted_message.size());

          acrastruct.insert(acrastruct.end(), header.begin(), header.end());
          acrastruct.insert(acrastruct.end(), temp_public_key.begin(), temp_public_key.end());
          acrastruct.insert(acrastruct.end(), encrypted_symm_key.begin(), encrypted_symm_key.end());

          // todo: rewrite
          acrastruct.push_back(((uint8_t *) &em_length)[0]);
          acrastruct.push_back(((uint8_t *) &em_length)[1]);
          acrastruct.push_back(((uint8_t *) &em_length)[2]);
          acrastruct.push_back(((uint8_t *) &em_length)[3]);
          acrastruct.push_back(((uint8_t *) &em_length)[4]);
          acrastruct.push_back(((uint8_t *) &em_length)[5]);
          acrastruct.push_back(((uint8_t *) &em_length)[6]);
          acrastruct.push_back(((uint8_t *) &em_length)[7]);

          acrastruct.insert(acrastruct.end(), encrypted_message.begin(), encrypted_message.end());
          acrastruct.shrink_to_fit();

          return acrastruct;
        }

    private:
        const uint8_t symmetric_key_length = 32;

        // AcraStruct header format has eight ' symbols, 34 is ascii code of '
        const uint8_t acrastruct_header_byte = 34;
    };


} //acrawritercpp namespace


#endif