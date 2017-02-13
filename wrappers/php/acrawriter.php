<?php
#
# Copyright (c) 2015 Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
    function create_acrastruct($data, $acra_public_key, $context){
        $random_keypair=phpthemis_gen_ec_key_pair();
        $random_key=openssl_random_pseudo_bytes(32);
        $sm=phpthemis_secure_message_wrap($random_keypair['private_key'], $acra_public_key, $random_key);
        $encrypted_data = phpthemis_scell_seal_encrypt($random_key, $data, $context);
        $begin_tag = "\x22\x22\x22\x22\x22\x22\x22\x22";
        $encrypted_data_length = pack("P", strlen($encrypted_data));
        return $begin_tag . $random_keypair['public_key'] . $sm . $encrypted_data_length . $encrypted_data;
    }
?>