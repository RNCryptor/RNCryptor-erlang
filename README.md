# RNCryptor-Erlang

Erlang implementation of Rob Napier's <a href="https://github.com/RNCryptor/RNCryptor">RNCryptor</a> V3 data format for both password-based and key-based AES128 & AES256 encryption / decryption.

See <a
href="https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md">RNCryptor
V3</a> for more information.


## Notes

### Key Lengths

128-bit and 256-bit AES keys are supported.


### Key-Based Usage: encrypt/2 & decrypt/2

Function `encrypt/2` generates a random 32-bit Hmac Key and `decrypt/2` parses the first 32-bits of the RNPacket as the Hmac Key (per the RNCryptor V3 spec). 


    > Key256 = crypto:rand_bytes(32).
    
      <<102,95,113,93,223,178,0,103,196,34,189,16,41,238,16,55,
        170,218,37,146,219,181,161,182,228,116,185,182,17,130,161,134>>
    
    > RNPacket256 = rncryptor:encrypt(Key256, <<"dingo sky">>).
    
      <<221,66,120,25,237,0,2,15,154,157,146,212,231,250,107,73,
        80,92,45,221,99,27,194,86,20,58,236,127,105,60,112,121,
        3,0,181,96,160,2,195,119,25,183,113,27,161,33,148,75,
        133,90,113,57,191,231,98,62,194,229,26,204,201,14,162,113,
        216,152,170,194,133,161,113,1,239,219,189,223,147,10,101,128,
        37,235,64,17,178,10,219,250,138,6,219,179,255,169,131,21,
        254,102>>
    
    > rncryptor:decrypt(Key256, RNPacket256).
    
      <<"dingo sky">>


Utility functions are provided to create hex representations of binary values:

    > rncryptor_util:bin_to_hex(Key256).
    
      "665F715DDFB20067C422BD1029EE1037AADA2592DBB5A1B6E474B9B61182A186"

    > rncryptor_util:bin_to_hex(RNPacket).
    
      "DD427819ED00020F9A9D92D4E7FA6B49505C2DDD631BC256143AEC7F693C70790300B560A002C37719B7711BA121944B855A7139BFE7623EC2E51ACCC90EA271D898AAC285A17101EFDBBDDF930A658025EB4011B20ADBFA8A06DBB3FFA98315FE66"

Using 128-bit keys:

    > Key128 = crypto:rand_bytes(16).
    
      <<150,78,200,225,141,34,253,182,26,172,157,148,60,8,39,101>>

    > RNPacket128 = rncryptor:encrypt(Key128, <<"dingo sky">>).
    
      <<90,202,44,216,211,92,21,96,125,180,254,163,252,54,200,124,
        251,91,11,46,20,9,43,20,243,66,227,1,29,183,49,65,
        3,0,68,137,36,117,29,113,123,63,219,60,15,20,116,32,
        228,68,90,66,110,208,61,43,140,123,134,252,102,114,92,128,
        210,216,151,156,90,79,233,161,36,40,205,117,207,10,156,77,
        234,90,25,130,162,111,252,159,250,198,188,11,106,252,37,203,
        4,42>>

    > rncryptor:decrypt(Key128, RNPacket128).
    
      <<"dingo sky">>
      
### Key-Based Usage: encrypt/3 & decrypt/3

Functions `encrypt/3` and `decrypt/3` take an explicit Hmac Key value.

    > HmacKey = crypto:rand_bytes(32).
    
      <<11,228,218,183,82,229,34,121,247,147,30,69,223,47,199,121,
      79,183,114,20,147,146,162,78,219,27,127,207,197,1,66,211>>
      
    > RNCryptor = rncryptor:encrypt(Key256, HmacKey, <<"dingo sky">>).
    
      <<3,0,175,16,130,145,145,253,126,101,236,27,228,191,90,207,
        65,0,172,223,99,232,87,170,114,223,82,54,51,163,132,48,
        231,186,152,187,72,57,167,53,189,17,144,231,222,61,98,233,
        149,148,19,103,139,144,201,243,157,121,113,21,100,25,174,211,
        237,77>>
        
    > rncryptor:decrypt(Key256, HmacKey, RNCryptor).
    
      <<"dingo sky">>

Or, using `decrypt/2`:

    > RNPacket = <<HmacKey/binary, RNCryptor/binary>>.
    
      <<11,228,218,183,82,229,34,121,247,147,30,69,223,47,199,121,
        79,183,114,20,147,146,162,78,219,27,127,207,197,1,66,211,
        3,0,175,16,130,145,145,253,126,101,236,27,228,191,90,207,
        65,0,172,223,99,232,87,170,114,223,82,54,51,163,132,48,
        231,186,152,187,72,57,167,53,189,17,144,231,222,61,98,233,
        149,148,19,103,139,144,201,243,157,121,113,21,100,25,174,211,
        237,77>>
        
    > rncryptor:decrypt(Key256, RNPacket).
    
      <<"dingo sky">>

### Password-Based Usage:

    > RNCryptor = rncryptor:encrypt_pw(<<"super secret">>, <<"dingo sky">>).
    
      <<3,1,172,64,176,130,224,97,45,148,247,56,20,40,94,182,
        125,63,163,114,177,167,183,106,76,109,126,250,243,15,37,175,
        64,104,253,133,20,17,129,27,95,164,245,54,57,237,250,215,
        254,33,91,57,211,80,16,217,167,165,7,31,175,64,158,67,
        148,222,193,47,142,241,198,208,189,217,75,255,28,140,71,5,
        134,253>>
        
    > rncryptor:decrypt_pw(<<"super secret">>, RNCryptor).
    
      <<"dingo sky">>
      
### Development Environment
 * Developed on Mac OS X 10.10 using Erlang 17.5.
 * Use <a href="https://github.com/rebar/rebar">rebar</a> to:
    * **rebar compile** : _Compile source_
    * **rebar eunit** : _Run all 54 eunit tests_
    * **rebar doc** : _Generate documentation_


### Licence
<a href="http://opensource.org/licenses/MIT">MIT</a>

