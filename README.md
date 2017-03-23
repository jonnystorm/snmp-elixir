# snmp-elixir

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

## What I'm currently stuck on

  * Getting SNMPv3 USM to work (shit is hard)
  * USM engineID discovery (a la [RFC 3414](https://tools.ietf.org/html/rfc3414#section-4))

## TODO

  * SNMPv3 USM
  * SNMP tables
  * MIB name resolution
  * Basic SNMP operations
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

