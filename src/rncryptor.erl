%%
%% @doc RNCryptor v3 encryption and decryption
%%
-module(rncryptor).
-author("paul@knoxen.com").

%%======================================================================================
%% API functions
%%======================================================================================
-export([encrypt/2, encrypt/3]).
-export([decrypt/2, decrypt/3]).

-export([encrypt_pw/2, encrypt_pw/4]).
-export([decrypt_pw/2]).

%%======================================================================================
%% Exposed testing functions
%%======================================================================================
-export([encrypt_key/4]).
-export([encrypt_pw/6]).

%%======================================================================================
%% RN header value constants
%%======================================================================================
-define(RN_V3,      3).
-define(RN_OPT_KEY, 0).
-define(RN_OPT_PW,  1).

%%======================================================================================
%% Sizes in bytes
%%======================================================================================
-define(AES_KEY_SIZE_128, 16).
-define(AES_KEY_SIZE_256, 32).

-define(PW_HMAC_KEY_SIZE, 32).

-define(KDF_SALT_SIZE,     8).
-define(HMAC_SALT_SIZE,    8).

-define(HMAC_SHA256_SIZE, 32).

-define(AES256_IVEC_SIZE, 16).

%%======================================================================================
%% Defined types
%%======================================================================================
-type salt64()    :: <<_:8>>.
-type aes_block() :: <<_:16>>.
-type key128()    :: <<_:16>>.
-type key256()    :: <<_:32>>.
-type aes_key()   :: key128() | key256().
-type hmac_key()  :: key256().
-type hmac_sig()  :: <<_:32>>.

-type rnversion() :: <<_:1>>.
-type rnoptions() :: <<_:1>>.
-type rnheader()  :: [rnversion() | rnoptions()].

-type rn_pw_cryptor()  :: [rnheader() | salt64() | salt64() | aes_block() | binary() | hmac_sig()].
-type rn_key_cryptor() :: [rnheader() | aes_block() | binary() | hmac_sig()].
-type rncryptor()      :: rn_pw_cryptor() | rn_key_cryptor().
-type rnpacket()       :: [hmac_key() | rncryptor()].

%%======================================================================================
%%
%% Key based encryption
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Encrypt plaintext with given key. A random 32-bit hmac key used for signing is
%% prepended to the RNCryptor to form the return packet.
%%
-spec encrypt(Key, PlainText) -> RNPacket | {error, Reason} when
    Key       :: aes_key(),
    PlainText :: binary(),
    RNPacket  :: rnpacket(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
encrypt(<<Key/binary>>, <<PlainText/binary>>) ->
  %% HmacKey len set equal to Key len
  HmacKey = crypto:strong_rand_bytes(?HMAC_SHA256_SIZE),
  case encrypt(Key, HmacKey, PlainText) of
    {error, Reason} ->
      {error, Reason};
    RNCryptor ->
      <<HmacKey/binary, RNCryptor/binary>>
  end;
encrypt(_Key, <<_PlainText/binary>>) ->
  {error, "Invalid encryption key"};
encrypt(<<_Key/binary>>, _PlainText) ->
  {error, "Invalid plaintext"}.

%%--------------------------------------------------------------------------------------
%% @doc Encrypt plaintext with key and sign the rncryptor with the hmac key.
%%
-spec encrypt(Key, HmacKey, PlainText) -> RNCryptor | {error, Reason} when
    Key       :: aes_key(),
    HmacKey   :: binary(),
    PlainText :: binary(),
    RNCryptor :: rncryptor(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
encrypt(<<Key/binary>>, <<HmacKey/binary>>, <<PlainText/binary>>) ->
  case byte_size(Key) of
    KeySize when KeySize =:= ?AES_KEY_SIZE_128;
                 KeySize =:= ?AES_KEY_SIZE_256 ->
      IVec = crypto:strong_rand_bytes(?AES256_IVEC_SIZE),
      encrypt_key(Key, IVec, HmacKey, PlainText);
    _ ->
      {error, "Invalid encryption key len"}
  end;
encrypt(_Key, <<_HmacKey/binary>>, <<_PlainText/binary>>) ->
  {error, "Invalid key"};
encrypt(<<_Key/binary>>, _HmacKey, <<_PlainText/binary>>) ->
  {error, "Invalid hmac key"};
encrypt(<<_Key/binary>>, <<_HmacKey/binary>>, _PlainText) ->
  {error, "Invalid plaintext"};
encrypt(_, _, _) ->
  {error, "Invalid args"}.

%%--------------------------------------------------------------------------------------
%% @doc Encrypt plaintext with key and ivec, and sign the rncryptor with the hmac
%% key. This function is exposed for testing purposes and should not be called
%% directly.
%%
-spec encrypt_key(Key, IVec, HmacKey, PlainText) -> RNCryptor | {error, Reason} when
    Key       :: aes_key(),
    IVec      :: binary(),
    HmacKey   :: binary(),
    PlainText :: binary(),
    RNCryptor :: rncryptor(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
encrypt_key(<<Key/binary>>,     <<IVec:?AES256_IVEC_SIZE/binary>>,
            <<HmacKey/binary>>, <<PlainText/binary>>) ->
  CipherIV = cipher_iv(byte_size(Key)),
  PaddedText = rncryptor_util:enpad(PlainText),
  CipherText = crypto:crypto_one_time(CipherIV, Key, IVec, PaddedText, true),
  Message = <<?RN_V3, ?RN_OPT_KEY, IVec/binary, CipherText/binary>>,
  RNHmac = crypto:hmac(sha256, HmacKey, Message, ?HMAC_SHA256_SIZE),
  <<Message/binary, RNHmac/binary>>;
encrypt_key(_Key, _IVec, _HmacKey, _PlainText) ->
  {error, "Invalid arguments"}.

%%======================================================================================
%%
%% Key based decryption
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Decrypt packet with given key. The first 32-bits of the packet are used to check
%% the mac value for the RNCryptor.
%%
-spec decrypt(Key, RNPacket) -> PlainText | {error, Reason} when
    Key       :: aes_key(),
    RNPacket  :: rnpacket(),
    PlainText :: binary(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
decrypt(<<Key/binary>>, <<RNPacket/binary>>) ->
  case RNPacket of
    <<HmacKey:?HMAC_SHA256_SIZE/binary, RNCryptor/binary>> ->
      decrypt(Key, HmacKey, RNCryptor);
    _ ->
      {error, "Invalid RN packet"}
  end;
decrypt(_Key, <<_RNPacket/binary>>) ->
  {error, "Invalid Key"};
decrypt(<<_Key/binary>>, _RNPacket) ->
  {error, "Invalid RN packet"};
decrypt(_, _) ->
  {error, "Invalid args"}.

%%--------------------------------------------------------------------------------------
%% @doc Use hmac key to verify signing of rncryptor, then decrypt the RNCryptor with key.
%%
-spec decrypt(Key, HmacKey, RNCryptor) -> PlainText | {error, Reason} when
    Key       :: aes_key(),
    HmacKey   :: binary(),
    PlainText :: binary(),
    RNCryptor :: rncryptor(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
decrypt(<<Key/binary>>, <<HmacKey/binary>>, <<RNCryptor/binary>>)
  when byte_size(Key) =:= ?AES_KEY_SIZE_128;
       byte_size(Key) =:= ?AES_KEY_SIZE_256 ->
  case parse_key_cryptor(HmacKey, RNCryptor) of
    {ok, IVec, CipherText} ->
      CipherIV = cipher_iv(byte_size(Key)),
      PaddedText = crypto:crypto_one_time(CipherIV, Key, IVec, CipherText, false),
      rncryptor_util:depad(PaddedText);
    Error ->
      Error
  end;
decrypt(<<_Key/binary>>, <<_HmacKey/binary>>, <<_RNCryptor/binary>>) ->
  {error, "Invalid key len"};
decrypt(<<_Key/binary>>, _HmacKey, <<_RNCryptor/binary>>) ->
  {error, "Invalid Hmac Key"};
decrypt(<<_Key/binary>>, <<_HmacKey/binary>>, _RNCryptor) ->
  {error, "Invalid RN cryptor"};
decrypt(_Key, _HmacKey, _RNCryptor) ->
  {error, "Invalid args"}.

%%======================================================================================
%%
%% Password based encryption
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Encrypt plaintext with the password. The key used for encryption and the hmac
%% key used for signing are both generated from the password via PBKDF2 with separate
%% random salts.
%%
-spec encrypt_pw(Password, PlainText) -> RNCryptor | {error, Reason} when
    Password  :: binary(),
    PlainText :: binary(),
    RNCryptor :: rncryptor(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
encrypt_pw(<<>>, _PlainText) ->
  {error, "Empty password"};
encrypt_pw(Password, PlainText) ->
  {KdfSalt,  KdfKey}  = rncryptor_kdf:pbkdf2(Password),
  {HmacSalt, HmacKey} = rncryptor_kdf:pbkdf2(Password),
  encrypt_pw(KdfSalt, KdfKey, HmacSalt, HmacKey, PlainText).

%%--------------------------------------------------------------------------------------
%% @doc Encrypt plaintext with the password. The key used for encryption and the hmac
%% key used for signing are both generated from the password via PBKDF2 using the
%% specified salts.
%%
-spec encrypt_pw(Password, KdfSalt, HmacSalt, PlainText) -> RNCryptor | {error, Reason} when
    Password  :: binary(),
    KdfSalt   :: salt64(),
    HmacSalt  :: salt64(),
    PlainText :: binary(),
    RNCryptor :: rncryptor(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
encrypt_pw(Password, KdfSalt, HmacSalt, PlainText) ->
  KdfKey = rncryptor_kdf:pbkdf2(Password, KdfSalt),
  HmacKey = rncryptor_kdf:pbkdf2(Password, HmacSalt),
  encrypt_pw(KdfSalt, KdfKey, HmacSalt, HmacKey, PlainText).

%%--------------------------------------------------------------------------------------
%% @private
%%--------------------------------------------------------------------------------------
encrypt_pw(KdfSalt, KdfKey, HmacSalt, HmacKey, PlainText) ->
  IVec = crypto:strong_rand_bytes(?AES256_IVEC_SIZE),
  encrypt_pw(KdfSalt, KdfKey, IVec, HmacSalt, HmacKey, PlainText).

%%--------------------------------------------------------------------------------------
%% @doc Encrypt plaintext with specified inputs. This function is exposed for testing
%% purposes and should not be called directly.
%%
-spec encrypt_pw(KdfSalt, KdfKey, IVec, HmacSalt, HmacKey, PlainText) -> RNCryptor when
    KdfSalt   :: salt64(),
    KdfKey    :: key256(),
    IVec      :: aes_block(),
    HmacSalt  :: salt64(),
    HmacKey   :: key256(),
    PlainText :: binary(),
    RNCryptor :: rncryptor().
%%--------------------------------------------------------------------------------------
encrypt_pw(KdfSalt, KdfKey, IVec, HmacSalt, HmacKey, PlainText) ->
  CipherIV = cipher_iv(byte_size(KdfKey)),
  PaddedText = rncryptor_util:enpad(PlainText),
  CipherText = crypto:crypto_one_time(CipherIV, KdfKey, IVec, PaddedText, true),
  RNData = <<?RN_V3, ?RN_OPT_PW, KdfSalt/binary, HmacSalt/binary, IVec/binary, CipherText/binary>>,
  RNHmac = crypto:hmac(sha256, HmacKey, RNData, ?HMAC_SHA256_SIZE),
  <<RNData/binary, RNHmac/binary>>.

%%======================================================================================
%%
%% Password based encryption
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Decrypt rncryptor using password.
%%
-spec decrypt_pw(Password, RNCryptor) -> PlainText | {error, Reason} when
    Password  :: binary(),
    RNCryptor :: rncryptor(),
    PlainText :: binary(),
    Reason    :: string().
%%--------------------------------------------------------------------------------------
decrypt_pw(<<>>, _RNCryptor) ->
  {error, "Empty password"};
decrypt_pw(Password, <<RNCryptor/binary>>) ->
  case parse_pw_cryptor(Password, RNCryptor) of
    {ok, KdfKey, IVec, CipherText} ->
      CipherIV = cipher_iv(byte_size(KdfKey)),
      PaddedText = crypto:crypto_one_time(CipherIV, KdfKey, IVec, CipherText, false),
      rncryptor_util:depad(PaddedText);
    Error ->
      Error
  end;
decrypt_pw(_Password, _RNCryptor) ->
  {error, "Invalid RN cryptor"}.

%%======================================================================================
%%
%% Private
%%
%%======================================================================================
%% @private
parse_key_cryptor(<<HmacKey/binary>>, <<RNCryptor/binary>>) ->
  case RNCryptor of
    <<?RN_V3, ?RN_OPT_KEY, IVec:?AES256_IVEC_SIZE/binary, _Rest/binary>> ->
      case hmac_challenge(HmacKey, RNCryptor) of
        {ok, RNData} ->
          SkipSize = 2 + ?AES256_IVEC_SIZE,
          <<_Skip:SkipSize/binary, CipherText/binary>> = RNData,
          {ok, IVec, CipherText};
        Error ->
          Error
      end;
    _ ->
      {error, "Invalid key-based RN cryptor"}
  end.

%% @private
parse_pw_cryptor(Password, <<RNCryptor/binary>>) ->
  case RNCryptor of
    <<?RN_V3, ?RN_OPT_PW, KdfSalt:?KDF_SALT_SIZE/binary, HmacSalt:?HMAC_SALT_SIZE/binary, IVec:?AES256_IVEC_SIZE/binary, _Rest/binary>> ->
      HmacKey = rncryptor_kdf:pbkdf2(Password, HmacSalt),
      case hmac_challenge(HmacKey, RNCryptor) of
        {ok, RNData} ->
          KdfKey = rncryptor_kdf:pbkdf2(Password, KdfSalt),
          SkipSize = 2 + ?KDF_SALT_SIZE + ?HMAC_SALT_SIZE + ?AES256_IVEC_SIZE,
          <<_Skip:SkipSize/binary, CipherText/binary>> = RNData,
          {ok, KdfKey, IVec, CipherText};
        Error ->
          Error
      end;
    _ ->
      {error, "Invalid password-based RN cryptor"}
  end.

%% @private
hmac_challenge(HmacKey, RNCryptor) ->
  RNSize  = erlang:byte_size(RNCryptor),
  RNData = erlang:binary_part(RNCryptor, {0, RNSize-?HMAC_SHA256_SIZE}),
  RNHmac  = erlang:binary_part(RNCryptor, {RNSize,  -?HMAC_SHA256_SIZE}),
  Challenge = crypto:hmac(sha256, HmacKey, RNData, ?HMAC_SHA256_SIZE),
  case rncryptor_util:const_compare(RNHmac, Challenge) of
    true ->
      {ok, RNData};
    false ->
      {error, "Invalid Hmac"}
  end.

cipher_iv(16) -> aes_128_cbc;
cipher_iv(24) -> aes_192_cbc;
cipher_iv(32) -> aes_256_cbc.
