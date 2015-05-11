-module(rncryptor_util).
%%
%% @author Paul Rogers <paul@knoxen.com>
%%
%% @doc Miscellaneous utilities
%%
-author("paul@knoxen.com").

-export([ceil/1]).
-export([enpad/1, depad/1]).
-export([const_compare/2]).
-export([bin_to_hex/1, hex_to_bin/1]).

-define(AES256_BLOCK_SIZE, 16).    %%  AES uses 128-bit blocks (regardless of key size)

%%======================================================================================
%%
%% Integer ceiling
%%
%%======================================================================================
%% @doc Return integer ceiling of float. 
%%
-spec ceil(X) -> Ceiling when
    X       :: float(),
    Ceiling :: integer().
%%--------------------------------------------------------------------------------------
ceil(X) ->
  Tx = trunc(X),
  case (X - Tx) of
    Neg when Neg < 0 ->
      Tx;
    Pos when Pos > 0 ->
      Tx + 1;
    _ ->
      Tx
  end.

%%======================================================================================
%%
%% PKCS7 padding
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Pad binary input using PKCS7 scheme.
%%
-spec enpad(Bin) -> Padded when
    Bin    :: binary(),
    Padded :: binary().
%%--------------------------------------------------------------------------------------
enpad(Bin) ->
  enpad(Bin, ?AES256_BLOCK_SIZE-(byte_size(Bin) rem ?AES256_BLOCK_SIZE)).

%% @private
enpad(Bin, Len) ->
  Pad = list_to_binary(lists:duplicate(Len,Len)),
  <<Bin/binary, Pad/binary>>.

%%--------------------------------------------------------------------------------------
%% @doc Remove padding from binary input using PKCS7 scheme.
%%
%% The last byte of the binary is the pad hex digit. Per <a
%% href="https://tools.ietf.org/html/rfc5652#section-6.3">RFC 5652 Section
%% 6.3</a>, "all input is padded, including input values that are already a
%% multiple of the block size", i.e., there should be a padding of k values of
%% k when len mod k = 0. However, if len mod k = 0 AND the last byte is greater
%% than k, padding with k values of k can be viewed as being superfluous since
%% the last byte is unambiguously not a padding value.  Some implementations
%% don't add padding in this case, i.e. if the last byte is greater than k we
%% interpret as no padding.
%% 
-spec depad(Padded :: binary()) -> Bin | {error, Reason} when
    Bin    :: binary(),
    Reason :: string().
%%--------------------------------------------------------------------------------------
depad(Bin) ->
  Len = byte_size(Bin),
  Pad = binary:last(Bin),
  case Pad =< ?AES256_BLOCK_SIZE of
    true ->
      %% The last byte less-equal than our block size and hence represents a padding value
      BinPad = list_to_binary(lists:duplicate(Pad, Pad)),
      %% verify the padding is indeed k values of k and return the unpadded data
      DataLen = Len - Pad,
      case Bin of
        <<Data:DataLen/binary, BinPad/binary>> ->
          Data;
        _ ->
          {error, "Data not properly padded"}
      end;
    false ->
      %% The last byte is greater than our block size; we interpret as no padding
      Bin
  end.

%%======================================================================================
%%
%% Compare binaries for equality
%%
%%======================================================================================
%% @doc Compare two binaries for equality, bit-by-bit, without short-circuits
%% to avoid timing differences.
%% 
-spec const_compare(Bin1, Bin2) -> boolean() when
    Bin1 :: binary(),
    Bin2 :: binary().
%%--------------------------------------------------------------------------------------
const_compare(<<X/binary>>, <<Y/binary>>) ->
  case byte_size(X) == byte_size(Y) of
    true ->
      const_compare(X, Y, true);
    false ->
      false
  end;
const_compare(_X, _Y) ->
  false.

%% @private
const_compare(<<X:1/bitstring, XT/bitstring>>, <<Y:1/bitstring, YT/bitstring>>, Acc) ->
  const_compare(XT, YT, (X == Y) and Acc);
const_compare(<<>>, <<>>, Acc) ->
  Acc.

%%======================================================================================
%%
%% Conversions for hex to binary to hex
%%
%%======================================================================================

%%--------------------------------------------------------------------------------------
%% @doc Convert binary to hex string.
%%
-spec bin_to_hex(Bin) -> Hex when
    Bin :: binary(),
    Hex :: string().
%%--------------------------------------------------------------------------------------
bin_to_hex(Bin) ->
  lists:flatten([io_lib:format("~2.16.0B", [X]) ||
    X <- binary_to_list(Bin)]).

%%--------------------------------------------------------------------------------------
%% @doc Convert hex string to binary.
%%
-spec hex_to_bin(Hex) -> Bin when
    Hex :: string(),
    Bin :: binary().
%%--------------------------------------------------------------------------------------
hex_to_bin(S) when is_list(S) ->
  hex_to_bin(S, []);
hex_to_bin(B) when is_binary(B) ->
  hex_to_bin(binary_to_list(B), []).

%% @private
hex_to_bin([], Acc) ->
  list_to_binary(lists:reverse(Acc));
hex_to_bin([X,Y|T], Acc) ->
  {ok, [V], []} = io_lib:fread("~16u", [X,Y]),
  hex_to_bin(T, [V | Acc]).
