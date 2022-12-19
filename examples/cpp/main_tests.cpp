#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include <iostream>
#include <vector>
#include <random>

#include <catch.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_lower.hpp>

#include "acrawriter.hpp"
#include <themis/themis.h>
#include <themispp/secure_cell.hpp>
#include <themispp/secure_message.hpp>
#include <themispp/secure_keygen.hpp>

using acra = acrawriter::acrawriter;
using base64 = cppcodec::base64_rfc4648;
using hex = cppcodec::hex_lower;
using namespace std;
using namespace themispp;

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

void generate_acrastruct_and_check_structure(uint64_t random_data_length) {
  cout << "generating AcraStruct with size: " << random_data_length << endl;

  // generate random data
  using random_bytes_engine = independent_bits_engine<default_random_engine, CHAR_BIT, uint8_t>;
  random_bytes_engine rbe;
  vector<uint8_t> random_data(random_data_length);
  generate(begin(random_data), end(random_data), ref(rbe));

  secure_key_pair_generator_t<EC> key_pair_generator;
  acra::data temp_private_key = key_pair_generator.get_priv();
  acra::data temp_public_key = key_pair_generator.get_pub();

  // pack acrastruct
  acra acrawriter;
  acra::acrastruct as = acrawriter.create_acrastruct(random_data, temp_public_key, null);

  REQUIRE (!as.empty());

  // header
  uint8_t header_length = 8;
  uint64_t as_start = 0;
  uint64_t as_end = as_start + header_length;

  acra::data header(header_length);
  copy(as.begin() + as_start, as.begin() + as_end, header.begin());
  REQUIRE (!header.empty());

  acra::data as_correct_header = {34, 34, 34, 34, 34, 34, 34, 34};
  REQUIRE (header == as_correct_header);

  // read inner public key, 45 bytes
  uint8_t public_key_length = 45;
  as_start = as_end;
  as_end = as_start + public_key_length;
  acra::data inner_public_key(public_key_length);
  copy(as.begin() + as_start, as.begin() + as_end, inner_public_key.begin());
  REQUIRE (!inner_public_key.empty());

  // create decryptor
  secure_message_t secure_message(temp_private_key, inner_public_key);

  // read encrypted symmetric key, 84 bytes
  uint8_t encrypted_symm_key_length = 84;
  as_start = as_end;
  as_end = as_start + encrypted_symm_key_length;

  acra::data encrypted_symm_key(encrypted_symm_key_length);
  copy(as.begin() + as_start, as.begin() + as_end, encrypted_symm_key.begin());
  REQUIRE (!encrypted_symm_key.empty());

  // decrypt symmetric key
  acra::data symmertic_key = secure_message.decrypt(encrypted_symm_key);
  REQUIRE (!symmertic_key.empty());

  // create decryptor
  secure_cell_seal_t secure_cell(symmertic_key);

  // read length of data, 8 bytes, little endian
  uint8_t encrypted_data_length_length = 8;
  as_start = as_end;
  as_end = as_start + encrypted_data_length_length;
  acra::data encrypted_data_length_vector(encrypted_data_length_length);
  copy(as.begin() + as_start, as.begin() + as_end, encrypted_data_length_vector.begin());

  if (is_big_endian()) {
    reverse(begin(encrypted_data_length_vector), end(encrypted_data_length_vector));
  }

  // check endianess
  uint64_t encrypted_data_length = *reinterpret_cast<const uint64_t*>(&encrypted_data_length_vector[0]);

  // read payload data
  as_start = as_end;
  as_end = as_start + encrypted_data_length;
  acra::data encrypted_data(encrypted_data_length);
  copy(as.begin() + as_start, as.begin() + as_end, encrypted_data.begin());
  REQUIRE (!encrypted_data.empty());

  // decrypt payload data
  acra::data payload = secure_cell.decrypt(encrypted_data, null);
  REQUIRE (!payload.empty());
  REQUIRE (payload == random_data);
}

TEST_CASE( "generate many acrastructs" ) {
  generate_acrastruct_and_check_structure(10); // 10 bytes
  generate_acrastruct_and_check_structure(100); // 100 bytes
  generate_acrastruct_and_check_structure(1024); // 1 kB
  generate_acrastruct_and_check_structure(1024 * 100); // 100 kB
  generate_acrastruct_and_check_structure(1024 * 1024); // 1 mB
//  generate_acrastruct_and_check_structure(1024 * 1024 * 100); // 10 mB
//  generate_acrastruct_and_check_structure(1024 * 1024 * 1024); // 1 GB
}

TEST_CASE ( " different acrastructs") {

  static string message_string("secret message");
  acra::data message_string_vector(message_string.c_str(), message_string.c_str() + message_string.length());

  secure_key_pair_generator_t<EC> key_pair_generator;
  acra::data temp_public_key = key_pair_generator.get_pub();

  // pack acrastruct
  acra acrawriter;
  acra::acrastruct as = acrawriter.create_acrastruct(message_string_vector, temp_public_key);
  REQUIRE (!as.empty());
}
