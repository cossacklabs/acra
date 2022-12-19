#ifndef ACRA_ACRAWRITER_
#define ACRA_ACRAWRITER_

#include <vector>
#include <random>

// themis should be installed as system library (run `make install` from Themis code folder)
// or check https://github.com/cossacklabs/themis/wiki/CPP-Howto
#include <themis/themis.h>

// themispp should be installed as system library (run `themispp_install` from Themis code folder)
// or check https://github.com/cossacklabs/themis/wiki/CPP-Howto
#include <themispp/secure_cell.hpp>
#include <themispp/secure_message.hpp>
#include <themispp/secure_keygen.hpp>

namespace acrawriter {

    using namespace themispp;
    using namespace std;

    class acrawriter {

    public:
        typedef vector<uint8_t> data;
        typedef vector<uint8_t> acrastruct;

        acrastruct create_acrastruct(const data &message, const data &public_key, const data &additionalContext) {
          return create_and_pack_acrastruct(message, public_key, additionalContext);
        }

        acrastruct create_acrastruct(const data &message, const data &public_key) {
          return create_and_pack_acrastruct(message, public_key);
        }

    private:
        // because it's always 32
        const uint8_t symmetric_key_length = 32;

        // AcraStruct header format has eight ' symbols, 34 is ascii code of '
        const uint8_t acrastruct_header_byte = 34;

        // private
        acrastruct create_and_pack_acrastruct(const data &message, const data &public_key, const data &additionalContext = data()) {
          // 1. generate EC keypair
          secure_key_pair_generator_t<EC> key_pair_generator;
          data temp_private_key = key_pair_generator.get_priv();
          data temp_public_key = key_pair_generator.get_pub();

          // 2. generate random symm key with `symmetric_key_length` size
          using random_bytes_engine = independent_bits_engine<default_random_engine, CHAR_BIT, uint8_t>;
          random_bytes_engine rbe;
          vector<uint8_t> symmertic_key(symmetric_key_length);
          generate(begin(symmertic_key), end(symmertic_key), ref(rbe));

          // 3. encrypt random symmetric key using asymmetric encryption with random private key and acra public key
          secure_message_t secure_message(temp_private_key, public_key);
          data encrypted_symm_key = secure_message.encrypt(symmertic_key);

          // zeroing temp_private_key key
          fill(temp_private_key.begin(), temp_private_key.end(), 0);

          // 4. encrypt payload using symmetric encryption and random symm key
          secure_cell_seal_t secure_cell(symmertic_key);
          data encrypted_message = additionalContext.empty() ? secure_cell.encrypt(message) : secure_cell.encrypt(message, additionalContext);

          // pack into array because I don't know how to push uint64_t into vector<uint8_t>
          uint64_t em_length = encrypted_message.size();
          uint8_t em_length_array[8];
          memcpy(em_length_array, &em_length, sizeof(em_length));

          // convert encrypted data length to little endian
          if (is_big_endian()) {
            reverse(begin(em_length_array), end(em_length_array));
          }

          // zeroing symmertic key
          fill(symmertic_key.begin(), symmertic_key.end(), 0);
          symmertic_key.clear();

          // 5. pack acrastruct

          // header is ''''''''
          data header = {acrastruct_header_byte, acrastruct_header_byte,
                           acrastruct_header_byte, acrastruct_header_byte,
                           acrastruct_header_byte, acrastruct_header_byte,
                           acrastruct_header_byte, acrastruct_header_byte};

          acrastruct acrastruct;
          acrastruct.reserve(header.size() + temp_public_key.size() + encrypted_symm_key.size() + sizeof(em_length) +
                             encrypted_message.size());

          acrastruct.insert(acrastruct.end(), header.begin(), header.end());
          acrastruct.insert(acrastruct.end(), temp_public_key.begin(), temp_public_key.end());
          acrastruct.insert(acrastruct.end(), encrypted_symm_key.begin(), encrypted_symm_key.end());
          acrastruct.insert(acrastruct.end(), em_length_array, em_length_array + sizeof(em_length_array));
          acrastruct.insert(acrastruct.end(), encrypted_message.begin(), encrypted_message.end());
          acrastruct.shrink_to_fit();

          return acrastruct;
        }

        /// https://github.com/steinwurf/endian/blob/master/src/endian/is_big_endian.hpp
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
    };

} //acrawriter namespace


#endif