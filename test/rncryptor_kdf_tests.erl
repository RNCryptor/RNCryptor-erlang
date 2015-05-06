-module(rncryptor_kdf_tests).

-author("paul@dingosky.com").

-include_lib("eunit/include/eunit.hrl").

-export([ietf_rfc_6070_vector_4/0]).

%%========================================================================================
%%
%% KDF Tests
%%
%%========================================================================================

%%---------------------------------------------------------------------------------------
%% Test vectors from IETF RFC 6070
%%
%%   https://www.ietf.org/rfc/rfc6070.txt
%%
%% Test vector 4 is quite long due to the high number of rounds. The test function
%% name purposely omits the _test ending so as to be excluded when running "all" tests.
%% The test is exported to allow running explicitly.
%%---------------------------------------------------------------------------------------

ietf_rfc_6070_vector_1_test() ->
  Expected = "0C60C80F961F0E71F3A9B524AF6012062FE037A6",
  test_pbkdf2(<<"password">>, <<"salt">>, 1, 20, Expected).

ietf_rfc_6070_vector_2_test() ->
  Expected = "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957",
  test_pbkdf2(<<"password">>, <<"salt">>, 2, 20, Expected).

ietf_rfc_6070_vector_3_test() ->
  Expected = "4B007901B765489ABEAD49D926F721D065A429C1",
  test_pbkdf2(<<"password">>, <<"salt">>, 4096, 20, Expected).

ietf_rfc_6070_vector_4() ->
  Expected = "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984",
  test_pbkdf2(<<"password">>, <<"salt">>, 16777216, 20, Expected).

ietf_rfc_6070_vector_5_test() ->
  Expected = "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038",
  test_pbkdf2(<<"passwordPASSWORDpassword">>, <<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>, 
              4096, 25, Expected).

ietf_rfc_6070_vector_6_test() ->
  Expected = "56FA6AA75548099DCC37D7F03425E0C3",
  test_pbkdf2(<<"pass\0word">>, <<"sa\0lt">>, 4096, 16, Expected).

%%---------------------------------------------------------------------------------------
%% Test vectors from RNCryptor v3:
%%
%%    https://github.com/RNCryptor/RNCryptor-Spec/blob/master/vectors/v3/kdf
%%---------------------------------------------------------------------------------------

rn_spec_v3_vector_1_test() ->
  Password = <<"a">>,
  Salt = rncryptor_util:hex_to_bin("0102030405060708"),
  Expected = "FC632B0CA6B23EFF9A9DC3E0E585167F5A328916ED19F83558BE3BA9828797CD",
  test_pbkdf2(Password, Salt, Expected).

rn_spec_v3_vector_2_test() ->
  Password = <<"thepassword">>,
  Salt = rncryptor_util:hex_to_bin("0203040506070801"),
  Expected = "0EA84F5252310DC3E3A7607C33BFD1EB580805FB68293005DA21037CCF499626",
  test_pbkdf2(Password, Salt, Expected).

rn_spec_v3_vector_3_test() ->
  Password = <<"this is a bit longer password">>,
  Salt = rncryptor_util:hex_to_bin("0304050607080102"),
  Expected = "71343ACB1E9675B016AC65DCFE5DDAC2E57ED9C35565FDBB2DD6D2CEFE263D5B",
  test_pbkdf2(Password, Salt, Expected).

rn_spec_v3_vector_4_test() ->
  Password = <<"$$$it was the epoch of belief, it was the epoch of incredulity; it was the season of Light, it was the season of Darkness; it was the spring of hope, it was the winter of despair; we had everything before us, we had nothing before us; we were all going directly to Heaven, we were all going the other way.">>,
  Salt = rncryptor_util:hex_to_bin("0405060708010203"),
  Expected = "11B52C50CBF45BE6A636A3142B8C30B85A6244814A7D43E37457F38DE46C6735",
  test_pbkdf2(Password, Salt, Expected).

rn_spec_v3_vector_5_test() ->
  Password = rncryptor_util:hex_to_bin("E4B8ADE69687E5AF86E7A081"),
  Salt = rncryptor_util:hex_to_bin("0506070801020304"),
  Expected = "D2FC3237D4A69668CA83D969C2CDA1AC6C3684792B6644B1A90B2052007215DD",
  test_pbkdf2(Password, Salt, Expected).

rn_spec_v3_vector_6_test() ->
  P1 = rncryptor_util:hex_to_bin("E4B8ADE69687E5AF86E7A081"),
  P2 = <<" with a little English, too.">>,
  Password = << P1/binary, P2/binary >>,
  Salt = rncryptor_util:hex_to_bin("0607080102030405"),
  Expected = "46BDA5F465982A4740C728BC14C5DE5CC7FC4EEAF0AA41BB9B9E8495452DAFFF",
  test_pbkdf2(Password, Salt, Expected).

%%========================================================================================
%%
%% Convenience functions
%%
%%========================================================================================
test_pbkdf2(Password, Salt, Expected) ->
  Value = rncryptor_kdf:pbkdf2(Password, Salt),
  ?assertEqual(Expected, rncryptor_util:bin_to_hex(Value)).

test_pbkdf2(Password, Salt, Rounds, KeySize, Expected) ->
  Value = rncryptor_kdf:pbkdf2(Password, Salt, Rounds, KeySize),
  ?assertEqual(Expected, rncryptor_util:bin_to_hex(Value)).

