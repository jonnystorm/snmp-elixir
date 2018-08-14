#!/bin/bash

function run
{
  mix clean &&
    ERL_COMPILER_OPTIONS=bin_opt_info mix compile --force &&
    mix test &&
    env MIX_ENV=test mix dialyzer --halt-exit-status
}

clear
run

while true
do
  inotifywait --exclude \..*\.sw. -re modify .
  clear
  run
done
