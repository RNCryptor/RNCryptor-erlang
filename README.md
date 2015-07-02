# RNCryptor-Erlang

Erlang implementation of Rob Napier's <a href="https://github.com/RNCryptor/RNCryptor">RNCryptor</a> V3 data format for both password-based and key-based AES128 & AES256 encryption / decryption.

See <a
href="https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md">RNCryptor
V3</a> for more information.


## Notes

### Basic Key-Based Usage

    > Key = crypto:rand_bytes(32).

      <<149,72,82,78,217,249,157,63,128,224,0,230,192,75,164,214, 
        148,58,220,158,250,92,89,209,104,186,148,135,184,193,125,162>>
    
    > RNPacket = rncryptor:encrypt(Key, <<"dingo sky">>).
    
      <<222,97,191,131,20,230,14,168,81,197,40,78,74,51,157,9,
        35,166,228,122,117,243,174,15,96,155,66,254,62,227,194,10,
        3,0,225,134,113,238,171,34,237,124,255,4,254,19,195,60,
        255,188,44,185,84,77,202,245,187,130,35,218,114,161,2,197,
        252,40,44,68,253,228,35,102,206,42,117,145,149,18,251,33,
        0,123,173,102,193,252,109,77,121,173,140,78,135,152,149,66,
        179,9>>
    
    > rncryptor:decrypt(Key, RNPacket).

      <<"dingo sky">>

Utility functions provide hex representations of the binary values:

    > rncryptor_util:bin_to_hex(Key).
    
      "BCFF7868DE8469A68BC4E51228173137C92E072506FA800AAF41D7459B56B829"

    > rncryptor_util:bin_to_hex(RNPacket).

      "7D87FC35C4DAC7E24ED3BE1A0FB58A97119F71BBF619ECEFD5B8E3EB9453A007030049ABF40D8156F006612523BE02527EA43A6C6D204F2CF8FBA99DF781CC941F82FC53432FFE32B944A5C37F7724FABF05D8B7393AF72FE3BCB7CA6D026B2E0885"

### Key Lengths

128-bit and 256-bit AES keys are supported.


### Minor Extension for Key-Based Operation

**RNCryptor Erlang** adds a simple, minor extension beyond the RNCryptor spec for ease of encryption and decryption in what is, for me anyway, a common use case of key-based encryption. As show in the **Basic Key-Based Usage** section above, **encrypt/2** and **decrypt/2** functions do not require specifying the HMAC key. Those functions operate on what I called an **RNPacket**, which is equal to **HmacKey \| RNCryptor**. **encrypt/2** auto-generates an HMAC key of length equal to the specified AES key, whereas **decrypt/2** assumes the HMAC key is of equal length to the specified AES key.

### Development Environment
 * Developed on Mac OS X 10.10 using Erlang 17.5.
 * Use <a href="https://github.com/rebar/rebar">rebar</a> to:
    * **rebar compile** : _Compile source_
    * **rebar eunit** : _Run all 54 eunit tests_
    * **rebar doc** : _Generate documentation_


### Licence
<a href="http://opensource.org/licenses/MIT">MIT</a>

