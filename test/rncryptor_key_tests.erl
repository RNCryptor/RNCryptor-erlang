-module(rncryptor_key_tests).

-author("paul@dingosky.com").

-include_lib("eunit/include/eunit.hrl").

-define(HMAC_SHA256_SIZE, 32).

%%========================================================================================
%%
%% Key Encryption Tests
%%
%%========================================================================================

%%----------------------------------------------------------------------------------------
%%
%% Test vectors from RNCryptor v3:
%%
%%    https://github.com/RNCryptor/RNCryptor-Spec/blob/master/vectors/v3/key
%%
%%----------------------------------------------------------------------------------------
rn_spec_v3_key_all_fields_empty_or_zero_encrypt_test() ->
  HexEncKey   = "0000000000000000000000000000000000000000000000000000000000000000",
  HexHmacKey  = "0000000000000000000000000000000000000000000000000000000000000000",
  HexIVec     = "00000000000000000000000000000000",
  PlainText   = <<>>,
  HexExpected = "0300000000000000000000000000000000001F788FE6D86C317549697FBF0C07FA436384AC0EF35B860B2DDB2ABA2FFF816B1FB3A9C180F7B43650AEC0D2B5F88E33",
  test_key_encrypt(HexEncKey, HexHmacKey, HexIVec, PlainText, HexExpected).

rn_spec_v3_key_all_fields_empty_or_zero_decrypt_test() ->
  HexEncKey    = "0000000000000000000000000000000000000000000000000000000000000000",
  HexHmacKey   = "0000000000000000000000000000000000000000000000000000000000000000",
  HexRNCryptor = "0300000000000000000000000000000000001F788FE6D86C317549697FBF0C07FA436384AC0EF35B860B2DDB2ABA2FFF816B1FB3A9C180F7B43650AEC0D2B5F88E33",
  HexExpected  = <<>>,
  test_key_decrypt(HexEncKey, HexHmacKey, HexRNCryptor, HexExpected).

rn_spec_v3_key_one_byte_encrypt_test() ->
  HexEncKey   = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F",
  HexHmacKey  = "0102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F00",
  HexIVec     = "02030405060708090a0b0c0d0e0f0001",
  PlainText   = <<1>>,
  HexExpected = "030002030405060708090A0B0C0D0E0F0001981B22E7A6448118D695BD654F72E9D6ED75EC14AE2AA067EED2A98A56E0993DFE22AB5887B3F6E3CDD40767F5195EB5",
  test_key_encrypt(HexEncKey, HexHmacKey, HexIVec, PlainText, HexExpected).

rn_spec_v3_key_one_byte_decrypt_test() ->
  HexEncKey    = "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F",
  HexHmacKey   = "0102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F00",
  HexRNCryptor = "030002030405060708090A0B0C0D0E0F0001981B22E7A6448118D695BD654F72E9D6ED75EC14AE2AA067EED2A98A56E0993DFE22AB5887B3F6E3CDD40767F5195EB5",
  HexExpected  = <<1>>,
  test_key_decrypt(HexEncKey, HexHmacKey, HexRNCryptor, HexExpected).

rn_spec_v3_exactly_one_block_encrypt_test() ->
  HexEncKey   = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00",
  HexHmacKey  = "02030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001",
  HexIVec     = "030405060708090a0b0c0d0e0f000102",
  PlainText   = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
  HexExpected = "0300030405060708090A0B0C0D0E0F000102D2B177D618781829F56453F739A2D4F729F92B1A9C6C5083786474E16A22C60F92B073454F7976CDDA043E09B11766DE05FFE05BC1DCA9522EA66E64AD25BBBC",
  test_key_encrypt(HexEncKey, HexHmacKey, HexIVec, PlainText, HexExpected).

rn_spec_v3_exactly_one_block_decrypt_test() ->
  HexEncKey    = "0102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00",
  HexHmacKey   = "02030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001",
  HexRNCryptor = "0300030405060708090A0B0C0D0E0F000102D2B177D618781829F56453F739A2D4F729F92B1A9C6C5083786474E16A22C60F92B073454F7976CDDA043E09B11766DE05FFE05BC1DCA9522EA66E64AD25BBBC",
  HexExpected  = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
  test_key_decrypt(HexEncKey, HexHmacKey, HexRNCryptor, HexExpected).

rn_spec_v3_more_than_one_block_encrypt_test() ->
  HexEncKey    = "02030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001",
  HexHmacKey   = "030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102",
  HexIVec      = "0405060708090a0b0c0d0e0f00010203",
  PlainText    = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8>>,
  HexExpected  = "03000405060708090A0B0C0D0E0F000102034C9B98B425F1D732644CB311278D858E3D182A0789B86AF7F74134B6A27E9D938617741C0FB8AAF094B3B5B26F505DA7BF1913F6C17E70273977AE51323B6F09",
  test_key_encrypt(HexEncKey, HexHmacKey, HexIVec, PlainText, HexExpected).

rn_spec_v3_more_than_one_block_decrypt_test() ->
  HexEncKey    = "02030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001",
  HexHmacKey   = "030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102",
  HexRNCryptor = "03000405060708090A0B0C0D0E0F000102034C9B98B425F1D732644CB311278D858E3D182A0789B86AF7F74134B6A27E9D938617741C0FB8AAF094B3B5B26F505DA7BF1913F6C17E70273977AE51323B6F09",
  HexExpected  = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,0,1,2,3,4,5,6,7,8>>,
  test_key_decrypt(HexEncKey, HexHmacKey, HexRNCryptor, HexExpected).

%%----------------------------------------------------------------------------------------
%%
%% Key encrypt/decrypt tests
%%
%%----------------------------------------------------------------------------------------

encrypt2_decrypt2_128_test() ->
  HexEncKey = "000102030405060708090A0B0C0D0E0F",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
  RNPacket = rncryptor:encrypt(EncKey, PlainTextIn),
  PlainTextOut = rncryptor:decrypt(EncKey, RNPacket),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt2_decrypt3_128_test() ->
  HexEncKey = "0102030405060708090A0B0C0D0E0F10",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<0,1,2,3,4,5,6,7,8>>,
  <<HmacKey:?HMAC_SHA256_SIZE/binary, RNCryptor/binary>> = rncryptor:encrypt(EncKey, PlainTextIn),
  PlainTextOut = rncryptor:decrypt(EncKey, HmacKey, RNCryptor),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt3_decrypt2_128_test() ->
  HexEncKey  = "02030405060708090A0B0C0D0E0F1011",
  HexHmacKey = "11100F0E0D0C0B0A090807060504030202030405060708090A0B0C0D0E0F1011",
  [EncKey, HmacKey] = hex_args_to_bin([HexEncKey, HexHmacKey]),
  PlainTextIn  = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17>>,
  RNCryptor    = rncryptor:encrypt(EncKey, HmacKey, PlainTextIn),
  RNPackage = <<HmacKey/binary, RNCryptor/binary>>,
  PlainTextOut = rncryptor:decrypt(EncKey, RNPackage),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt3_decrypt3_128_test() ->
  HexEncKey  = "030405060708090A0B0C0D0E0F101112",
  HexHmacKey = "1211100F0E0D0C0B0A09080706050403",
  [EncKey, HmacKey] = hex_args_to_bin([HexEncKey, HexHmacKey]),
  PlainTextIn  = <<"the quick brown fox jumps over the lazy dog">>,
  RNCryptor    = rncryptor:encrypt(EncKey, HmacKey, PlainTextIn),
  PlainTextOut = rncryptor:decrypt(EncKey, HmacKey, RNCryptor),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt2_decrypt2_256_test() ->
  HexEncKey  = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<255,254,01,00>>,
  RNPacket = rncryptor:encrypt(EncKey, PlainTextIn),
  PlainTextOut = rncryptor:decrypt(EncKey, RNPacket),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt2_decrypt3_256_test() ->
  HexEncKey  = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<255,254,253,252,251,250,249,248,7,6,5,4,3,2,1,0>>,
  <<HmacKey:?HMAC_SHA256_SIZE/binary, RNCryptor/binary>> = rncryptor:encrypt(EncKey, PlainTextIn),
  PlainTextOut = rncryptor:decrypt(EncKey, HmacKey, RNCryptor),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt3_decrypt2_256_test() ->
  HexEncKey  = "02030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021",
  HexHmacKey = "21201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A0908070605040302",
  [EncKey, HmacKey] = hex_args_to_bin([HexEncKey, HexHmacKey]),
  PlainTextIn  = <<"the qu1ck brown fox jump$ over The lazy dog">>,
  RNCryptor    = rncryptor:encrypt(EncKey, HmacKey, PlainTextIn),
  RNPackage = <<HmacKey/binary, RNCryptor/binary>>,
  PlainTextOut = rncryptor:decrypt(EncKey, RNPackage),
  ?assertEqual(PlainTextIn, PlainTextOut).

encrypt3_decrypt3_256_test() ->
  HexEncKey  = "030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122",
  HexHmacKey = "2221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403",
  [EncKey, HmacKey] = hex_args_to_bin([HexEncKey, HexHmacKey]),
  PlainTextIn  = <<"&">>,
  RNCryptor    = rncryptor:encrypt(EncKey, HmacKey, PlainTextIn),
  PlainTextOut = rncryptor:decrypt(EncKey, HmacKey, RNCryptor),
  ?assertEqual(PlainTextIn, PlainTextOut).

%%========================================================================================
%%
%% Invalid args tests
%%
%%========================================================================================
encrypt_invalid_key_length_test() ->
  EncKey    = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
  PlainText = <<"hey, now">>,
  Expected  = "Invalid encryption key len",
  {error, Reason} = rncryptor:encrypt(EncKey, PlainText),
  ?assertEqual(Expected, Reason).

encrypt_enc_key_not_binary_test() ->
  EncKey    = "key",
  PlainText = <<"hey, now">>,
  Expected  = "Invalid encryption key",
  {error, Reason} = rncryptor:encrypt(EncKey, PlainText),
  ?assertEqual(Expected, Reason).

encrypt_hmac_key_not_binary_test() ->
  EncKey    = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
  HmacKey   = invalid,
  PlainText = <<"hey, now">>,
  Expected  = "Invalid hmac key",
  {error, Reason} = rncryptor:encrypt(EncKey, HmacKey, PlainText),
  ?assertEqual(Expected, Reason).

encrypt_plaintext_not_binary_test() ->
  EncKey    = <<1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16>>,
  PlainText = "hey, now",
  Expected  = "Invalid plaintext",
  {error, Reason} = rncryptor:encrypt(EncKey, PlainText),
  ?assertEqual(Expected, Reason).

decrypt_invalid_hmac_1_test() ->
  HexEncKey  = "000102030405060708090A0B0C0D0E0F",
  HexHmacKey = "0102030405060708090A0B0C0D0E0F00",
  HexRNCryptor = "030002030405060708090A0B0C0D0E0F000198DC7E36E7CCCB0CB7E82B048C460825ECD54AD9B0933B236B748A1CE455EE1EC4E93043F60BE2ED50DCCFB3C4B2383D",
  [EncKey, HmacKey, RNCryptor] = hex_args_to_bin([HexEncKey, HexHmacKey, HexRNCryptor]),
  Expected  = "Invalid Hmac",
  {error, Reason} = rncryptor:decrypt(EncKey, HmacKey, RNCryptor),
  ?assertEqual(Expected, Reason).

decrypt_invalid_hmac_2_test() ->
  HexEncKey = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<255,254,01,00>>,
  RNPacket = rncryptor:encrypt(EncKey, PlainTextIn),
  PacketSizeMinus1 = byte_size(RNPacket) - 1,
  <<Blob:PacketSizeMinus1/binary, _LastBytes/binary>> = RNPacket,
  RNPacket2 = <<Blob/binary, 0>>,
  Expected  = "Invalid Hmac",
  {error, Reason} = rncryptor:decrypt(EncKey, RNPacket2),
  ?assertEqual(Expected, Reason).

decrypt_invalid_rncryptor_1_test() ->
  HexEncKey = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<255,254,01,00>>,
  RNPacket = rncryptor:encrypt(EncKey, PlainTextIn),
  FirstSize = byte_size(EncKey),
  <<First:FirstSize/binary, 3, 0, Rest/binary>> = RNPacket,
  RNPacket2 = <<First/binary, 2, 0, Rest/binary>>,
  Expected  = "Invalid key-based RN cryptor",
  {error, Reason} = rncryptor:decrypt(EncKey, RNPacket2),
  ?assertEqual(Expected, Reason).

decrypt_invalid_rncryptor_2_test() ->
  HexEncKey = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
  [EncKey] = hex_args_to_bin([HexEncKey]),
  PlainTextIn  = <<255,254,01,00>>,
  RNPacket = rncryptor:encrypt(EncKey, PlainTextIn),
  FirstSize = byte_size(EncKey),
  <<First:FirstSize/binary, 3, 0, Rest/binary>> = RNPacket,
  RNPacket2 = <<First/binary, 3, 1, Rest/binary>>,
  Expected  = "Invalid key-based RN cryptor",
  {error, Reason} = rncryptor:decrypt(EncKey, RNPacket2),
  ?assertEqual(Expected, Reason).

%%========================================================================================
%%
%% Convenience functions
%%
%%========================================================================================
test_key_encrypt(HexEncKey, HexHmacKey, HexIVec, PlainText, HexExpected) ->
  [EncKey, HmacKey, IVec, Expected] =
    hex_args_to_bin([HexEncKey, HexHmacKey, HexIVec, HexExpected]),
  RNCryptor =  rncryptor:encrypt_key(EncKey, IVec, HmacKey, PlainText),
  ?assertEqual(Expected, RNCryptor).

test_key_decrypt(HexEncKey, HexHmacKey, HexRNCryptor, Expected) ->
  [EncKey, HmacKey, RNCryptor] = hex_args_to_bin([HexEncKey, HexHmacKey, HexRNCryptor]),
  PlainText = rncryptor:decrypt(EncKey, HmacKey, RNCryptor),
  ?assertEqual(Expected, PlainText).

hex_args_to_bin(List) ->
  lists:map(fun(Arg) ->
                rncryptor_util:hex_to_bin(Arg)
            end,
            List).
