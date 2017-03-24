#!/bin/bash

while true; do
  inotifywait --exclude \..*\.sw. -re modify .
  clear
  mix test
done
