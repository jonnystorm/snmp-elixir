# snmp-elixir

[![Build Status](https://travis-ci.org/jonnystorm/snmp-elixir.svg?branch=master)](https://travis-ci.org/jonnystorm/snmp-elixir)
([graphs](http://scribu.github.io/travis-stats/#jonnystorm/snmp-elixir/master))

An SNMP client library for Elixir.

This is my effort to replace the terrible but useful
[net-snmp-elixir](https://github.com/jonnystorm/net-snmp-elixir) with a
facile Elixir wrapper for OTP's harrowing SNMP API.

Many thanks to Dave Martin for his
[post](https://groups.google.com/forum/#!topic/elixir-lang-talk/lGWGXFoUVvc),
without which I may never have bothered returning to this problem.

## Why another wrapper?

`net-snmp-elixir` was my experimental hack to get something that worked.
I didn't expect it to become one of the top Google results for "elixir snmp"
but it is, which scares me. Elixir may be the best language for network
interaction in existence, but we still need worthy SNMP support.

## Contributing

This project will accept (merge/rebase/squash) *all* contributions.
Contributions that break the build will be reverted.

For details, please see [Why Optimistic Merging Works Better](http://hintjens.com/blog:106).

## What we're currently stuck on

* USM engineID discovery (a la [RFC 3414](https://tools.ietf.org/html/rfc3414#section-4))

## TODO

* SNMPv3 USM (~~noAuthNoPriv~~, ~~authNoPriv~~, ~~authPriv-DES~~, authPriv-AES128)
* USM engine discovery
* SNMP tables
* ~~MIB name resolution~~
* Basic SNMP operations (~~GET~~, SET)
* Process management
* Make it decent

## Installation

Add `snmp_ex` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [ {:snmp_ex, git: "https://github.com/jonnystorm/snmp-elixir.git"},
  ]
end
```
