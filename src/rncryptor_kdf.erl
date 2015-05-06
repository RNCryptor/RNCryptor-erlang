%%
%% @author Paul Rogers <paul@dingosky.com>
%%
%% @doc Derive PassKey from Password using Key Derivation Function. RNCryptor V3 only
%% supports the KDF PBKDF2 using SHA1.
%%
%% @reference <a href="https://tools.ietf.org/html/rfc2898#section-5.2">IETF
%% RFC 2898 Section 5.2</a>
%%
-module(rncryptor_kdf).

-author("paul@dingosky.com").

-export([pbkdf2/1, pbkdf2/2, pbkdf2/3, pbkdf2/4]).

-define(PBKDF2_DEFAULT_SALT_SIZE,     8).
-define(PBKDF2_DEFAULT_ROUNDS,    10000).
-define(PBKDF2_DEFAULT_KEY_SIZE,     32).
-define(PBKDF2_SHA1_SIZE,            20).

%%--------------------------------------------------------------------------------------
%% @doc Generate random salt and derived PassKey using default number of rounds and
%% key size.
%%
-spec pbkdf2(Password) -> {Salt, PassKey} when
    Password   :: binary(),
    Salt       :: binary(),
    PassKey    :: binary().
%%--------------------------------------------------------------------------------------
pbkdf2(Password) ->
  Salt = crypto:rand_bytes(?PBKDF2_DEFAULT_SALT_SIZE),
  {Salt, pbkdf2(Password, Salt)}.

%%--------------------------------------------------------------------------------------
%% @doc Derive PassKey using salt and default number of rounds and key size.
%%
-spec pbkdf2(Password, Salt) -> PassKey when
    Password   :: binary(),
    Salt       :: binary(),
    PassKey    :: binary().
%%--------------------------------------------------------------------------------------
pbkdf2(Password, Salt) ->
  pbkdf2(Password, Salt, ?PBKDF2_DEFAULT_ROUNDS, ?PBKDF2_DEFAULT_KEY_SIZE).

%%--------------------------------------------------------------------------------------
%% @doc Derive PassKey using salt, number of rounds, and default key size.
%%
-spec pbkdf2(Password, Salt, Rounds) -> PassKey when
    Password   :: binary(),
    Salt       :: binary(),
    Rounds     :: integer(),
    PassKey    :: binary().
%%--------------------------------------------------------------------------------------
pbkdf2(Password, Salt, Rounds) ->
  pbkdf2(Password, Salt, Rounds, ?PBKDF2_DEFAULT_KEY_SIZE).

%%--------------------------------------------------------------------------------------
%% @doc Derive PassKey using salt, number of rounds, and key size.
%%
-spec pbkdf2(Password, Salt, Rounds, KeySize) -> PassKey when
    Password   :: binary(),
    Salt       :: binary(),
    Rounds     :: integer(),
    KeySize    :: integer(),
    PassKey    :: binary().
%%--------------------------------------------------------------------------------------
pbkdf2(Password, Salt, Rounds, KeySize) ->
  pbkdf2_key(Password, Salt, Rounds, KeySize, 1, <<>>).

%%======================================================================================
%%
%% Private
%%
%%======================================================================================
%% @private
pbkdf2_key(Password, Salt, Rounds, KeySize, BlockNum, PassKey) ->
  InitBlock = crypto:hmac(sha, Password, <<Salt/binary, BlockNum:32/integer>>, ?PBKDF2_SHA1_SIZE),
  BlockKey = pbkdf2_block_key(Password, Rounds, 2, InitBlock, InitBlock),
  NumBlocks = rncryptor_util:ceil(KeySize / ?PBKDF2_SHA1_SIZE),
  case BlockNum =:= NumBlocks of
    true ->
      LastBlockSize = KeySize - (NumBlocks-1)*?PBKDF2_SHA1_SIZE,
      <<PassKey/binary, BlockKey:LastBlockSize/binary>>;
    false ->
      pbkdf2_key(Password, Salt, Rounds, KeySize, BlockNum + 1, <<PassKey/binary, BlockKey/binary>>)
  end.

%% @private
pbkdf2_block_key(_Password, Rounds, Round, _PrevBlock, Block) when Round > Rounds ->
  Block;
pbkdf2_block_key(Password, Rounds, Round, PrevBlock, Block) ->
  NextBlock = crypto:hmac(sha, Password, PrevBlock, ?PBKDF2_SHA1_SIZE),
  Block2 = crypto:exor(NextBlock, Block),
  pbkdf2_block_key(Password, Rounds, Round + 1, NextBlock, Block2).


