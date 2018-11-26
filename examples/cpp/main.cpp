#include <iostream>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/hex_lower.hpp>

#include "acrawriter.hpp"

using acra = acrawriter::acrawriter;
using base64 = cppcodec::base64_rfc4648;
using hex = cppcodec::hex_lower;
using namespace std;

void create_acrastruct() {
  static string message("secret message");
  acra::data message_vector(message.c_str(), message.c_str() + message.length());

  vector<uint8_t> pub_key = base64::decode("VUVDMgAAAC1SGS5iAprH9f1sf7GR4OZ/J1YEn8lEwrgmI36G1JOnx7BITfK/");

  // init acrawriter
  acra acrawriter;

  // create acrastruct
  acra::acrastruct as = acrawriter.create_acrastruct(message_vector, pub_key);

  cout << "AcraStruct (hex):" << endl;
  cout << hex::encode(as) << endl;

  cout << "AcraStruct (Base64):" << endl;
  cout << base64::encode(as) << endl;
}

void create_acrastruct_with_zone() {
  static string message_with_zone("message with zone");
  acra::data message_with_zone_vector(message_with_zone.c_str(), message_with_zone.c_str() + message_with_zone.length());

  static string zone_id("DDDDDDDDvTOInNRROHOihRkf");
  acra::data zone_id_vector(zone_id.c_str(), zone_id.c_str() + zone_id.length());

  vector<uint8_t> zone_pub_key = base64::decode("VUVDMgAAAC1GQ4j5AgEwz22ion8C0lvwRGJSjaC/G6ver3oOqmbBrIBjpdRo");

  // init acrawriter
  acra acrawriter;

  // create acrastruct
  acra::acrastruct as_with_zone = acrawriter.create_acrastruct(message_with_zone_vector, zone_pub_key, zone_id_vector);

  cout << "AcraStruct with zone (hex):" << endl;
  cout << hex::encode(as_with_zone) << endl;

  cout << "AcraStruct with zone (Base64):" << endl;
  cout << base64::encode(as_with_zone) << endl;
}

int main() {

  create_acrastruct();
  create_acrastruct_with_zone();
  return 0;
}
