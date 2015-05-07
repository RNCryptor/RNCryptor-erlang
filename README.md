# RNCryptor-erlang

Erlang implementation of Rob Napier's <a href="https://github.com/RNCryptor/RNCryptor">RNCryptor</a> V3 data format for AES128 &
AES256 encryption / decryption. See <a
href="https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v3.md">RNCryptor
V3</a> for more information.


Full implementation of both password-based and key-based encryption.

## Notes
### Minor Extension
RNCryptor Erlang adds a minor extension for ease of encryption and decryption in what is, for me anyway, a common use case of key-based encryption of what I called an **RNPacket** = **HmacKey \| RNCryptor**.
  * Functions **_encrypt/2_** and **_decrypt/2_** operate on **RNPacket**s
  * **_encrypt/2_** auto-generates **HmacKey** of same size as encryption key to create an **RNPacket**
  * **_decrypt/2_** matches an **RNPacket** for an **HmacKey** of the same size as the encryption key


### Development Environment
 * Developed on Mac OS X 10.10 using Erlang 17.5.
 * Requires <a href="https://github.com/rebar/rebar">rebar</a> to:
    * **make** : Compile
    * **make test** : Run tests
    * **make doc** : Generate documentation


### Licence
MIT
