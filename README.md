# RNCryptor-erlang

Erlang implementation of Rob Napier's <a href="https://github.com/RNCryptor/RNCryptor">RNCryptor</a> V3 data format for AES128 &
AES256 encryption / decryption. See <a
href="https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md">RNCryptor
V3</a> for more information.


Full implementation of both password-based and key-based encryption.

## Notes

### Basic Key-based Usage

    > Key = crypto:rand_bytes(32).
    
    > Plaintext = <<"dingo sky">>.
    
    > RNPacket = rncryptor:encrypt(Key, Plaintext).
    
    > Plaintext = rncryptor:decrypt(Key, RNPacket).


That the **encrypt** / **decrypt** round-trip actually worked is ensured by the last line above, which would throw an error for no match of the right hand side if the result of the decryption call wasn't identical to the original **Plaintext** value.

Peaking at the hex representation of above values:

    > rncryptor_util:bin_to_hex(Key).
    "BCFF7868DE8469A68BC4E51228173137C92E072506FA800AAF41D7459B56B829"

    > rncryptor_util:bin_to_hex(RNPacket).
    "7D87FC35C4DAC7E24ED3BE1A0FB58A97119F71BBF619ECEFD5B8E3EB9453A007030049ABF40D8156F006612523BE02527EA43A6C6D204F2CF8FBA99DF781CC941F82FC53432FFE32B944A5C37F7724FABF05D8B7393AF72FE3BCB7CA6D026B2E0885"

### Key Lengths

128-bit and 256-bit AES keys are supported.


### Minor Extension
As show in the **Basic Key-based Usage** above, **RNCryptor Erlang** adds a minor extension for ease of encryption and decryption in what is, for me anyway, a common use case of key-based encryption of what I called an **RNPacket** = **HmacKey \| RNCryptor**.
  * Functions **_encrypt/2_** and **_decrypt/2_** operate on **RNPacket**s
  * **_encrypt/2_** auto-generates **HmacKey** of same size as encryption key to create an **RNPacket**
  * **_decrypt/2_** matches an **RNPacket** for an **HmacKey** of the same size as the encryption key


### Development Environment
 * Developed on Mac OS X 10.10 using Erlang 17.5.
 * Requires <a href="https://github.com/rebar/rebar">rebar</a> to:
    * **make** : _Compile_
    * **make test** : _Run tests_
    * **make doc** : _Generate documentation_


### Licence
The MIT License (MIT)

Copyright (c) 2015 Knoxen, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

<a href="http://opensource.org/licenses/MIT">MIT</a>
