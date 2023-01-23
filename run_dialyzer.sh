#!/usr/bin/env bash
# ELIXIR_VERSION=1.4.2 OTP_RELEASE=19.2 ./run_dialyzer.sh
export MIX_ENV=test

export PLT_FILENAME=elixir-${ELIXIR_VERSION}_${OTP_RELEASE}.plt
export PLT_TESTNAME=dialyxir_erlang-${OTP_RELEASE}_elixir-${ELIXIR_VERSION}_deps-${MIX_ENV}.plt
export PLT_LOCATION=_build/$MIX_ENV/$PLT_TESTNAME

mix dialyzer
