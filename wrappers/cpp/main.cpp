#include <iostream>
#include "cppcodec/base64_default_rfc4648.hpp"
#include "cppcodec/hex_default_lower.hpp"

#include "acrawriter.hpp"


int main() {
  std::cout << "Hello, World!" << std::endl;

  using acra = acrawriterpp::acrawriter_t;
  using base64 = cppcodec::base64_rfc4648;
  using hex = cppcodec::hex_lower;

  acra::data_t message = {'h', '3', 'l', 'l', '0', 'a', 'c', 'r', 'a'};

  std::vector<uint8_t> pub_key = base64::decode("VUVDMgAAAC1SGS5iAprH9f1sf7GR4OZ/J1YEn8lEwrgmI36G1JOnx7BITfK/");

  acra acrawriter;
  acra::acrastruct_t as = acrawriter.create_acra_struct(message, pub_key);

  std::cout << "AcraStruct B64:" << std::endl;
  std::cout << base64::encode(as) << std::endl;

  std::cout << "AcraStruct hex:" << std::endl;
  std::cout << hex::encode(as) << std::endl;

  std::cout << "Just AS:" << std::endl;
  std::cout.write((const char*)(&as[0]), as.size());

  return 0;
}