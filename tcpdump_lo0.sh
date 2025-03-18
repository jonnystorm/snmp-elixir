#!/usr/bin/env bash

sudo tcpdump -i lo0 -nn -s0 udp port 161 