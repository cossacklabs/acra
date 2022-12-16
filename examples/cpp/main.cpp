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

int main() {

  create_acrastruct();
  return 0;
}
