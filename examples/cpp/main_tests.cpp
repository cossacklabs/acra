#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"

#include <iostream>
#include <vector>
#include <random>
#include "cppcodec/base64_default_rfc4648.hpp"
#include "cppcodec/hex_default_lower.hpp"

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


void generate_acrastruct_and_check_structure(uint64_t random_data_length) {
  cout << "generating AcraStruct with size: " << random_data_length << endl;

  // generate random data
  using random_bytes_engine = independent_bits_engine<default_random_engine, CHAR_BIT, uint8_t>;
  random_bytes_engine rbe;
  vector<uint8_t> random_data(random_data_length);
  generate(begin(random_data), end(random_data), ref(rbe));

  static string zone_id_string("DDDDDDDDvTOInNRROHOihRkf");
  acra::data zone_id_vector(zone_id_string.c_str(), zone_id_string.c_str() + zone_id_string.length());

  secure_key_pair_generator_t<EC> key_pair_generator;
  acra::data temp_private_key = key_pair_generator.get_priv();
  acra::data temp_public_key = key_pair_generator.get_pub();

  // pack acrastruct
  acra acrawriter;
  acra::acrastruct as = acrawriter.create_acrastruct(random_data, temp_public_key, zone_id_vector);

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

  // check endianess
  uint64_t encrypted_data_length = *reinterpret_cast<const uint64_t*>(&encrypted_data_length_vector[0]);

  // read payload data
  as_start = as_end;
  as_end = as_start + encrypted_data_length;
  acra::data encrypted_data(encrypted_data_length);
  copy(as.begin() + as_start, as.begin() + as_end, encrypted_data.begin());
  REQUIRE (!encrypted_data.empty());

  // decrypt payload data
  acra::data payload = secure_cell.decrypt(encrypted_data, zone_id_vector);
  REQUIRE (!payload.empty());
  REQUIRE (payload == random_data);
}

TEST_CASE( "generate many acrastructs" ) {
  static string zone_id("DDDDDDDDvTOInNRROHOihRkf");
  acra::data zone_id_vector(zone_id.c_str(), zone_id.c_str() + zone_id.length());

  vector<uint8_t> zone_pub_key = base64::decode("VUVDMgAAAC1GQ4j5AgEwz22ion8C0lvwRGJSjaC/G6ver3oOqmbBrIBjpdRo");

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

  static string zone_id_string("DDDDDDDDvTOInNRROHOihRkf");
  acra::data zone_id_vector(zone_id_string.c_str(), zone_id_string.c_str() + zone_id_string.length());

  secure_key_pair_generator_t<EC> key_pair_generator;
  acra::data temp_private_key = key_pair_generator.get_priv();
  acra::data temp_public_key = key_pair_generator.get_pub();

  // pack acrastruct
  acra acrawriter;
  acra::acrastruct as_with_zone = acrawriter.create_acrastruct(message_string_vector, temp_public_key, zone_id_vector);

  REQUIRE (!as_with_zone.empty());

  acra::acrastruct as = acrawriter.create_acrastruct(message_string_vector, temp_public_key);
  REQUIRE (!as.empty());
}