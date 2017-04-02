#!/bin/bash

while true; do
  inotifywait --exclude \..*\.sw. -re modify .
  clear
    mix test --include integrated &&
    env MIX_ENV=test mix dialyzer --halt-exit-status
done
