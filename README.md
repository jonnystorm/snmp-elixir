# snmp-elixir

[![Build Status](https://gitlab.com/jonnystorm/snmp-elixir/badges/master/pipeline.svg)](https://gitlab.com/jonnystorm/snmp-elixir/commits/master)

An SNMP client library for Elixir.

This is my effort to replace the terrible but useful
[net-snmp-elixir](https://gitlab.com/jonnystorm/net-snmp-elixir)
with a facile Elixir wrapper for OTP's harrowing SNMP API.

Many thanks to Dave Martin for his
[post](https://groups.google.com/forum/#!topic/elixir-lang-talk/lGWGXFoUVvc),
without which I may never have bothered returning to this
problem.

## Usage in CLI

```elixir
iex> SNMP.start
iex>
iex> v2_cred = SNMP.Credential.login([:v2c, "public"])
%SNMP.Credential.Community{
  community: 'public',
  sec_model: :v2c,
  version: :v2
}
iex>
iex> {:ok, base_oid} =
...>   SNMP.resolve_object_name_to_oid(:sysName)
{:ok, [1, 3, 6, 1, 2, 1, 1, 5]}
iex>
iex> SNMP.get(base_oid ++ [0], "an-snmp-host.local", v2_cred)
[
  {[1, 3, 6, 1, 2, 1, 1, 5, 0], :"OCTET STRING", 'an-snmp-host'}
]
iex>
iex> v3_cred =
...>   SNMP.Credential.login(
...>     [ :v3,
...>       :auth_priv,
...>       "user",
...>       :sha,
...>       "authpass",
...>       :aes,
...>       "privpass",
...>     ]
...>  )
%SNMP.Credential.USM{
  auth: :sha,
  auth_pass: 'authpass',
  priv: :aes,
  priv_pass: 'privpass',
  sec_level: :authPriv,
  sec_model: :usm,
  sec_name: 'nms',
  version: :v3
}
iex> SNMP.walk("ipAddrTable", "an-snmp-host.local", v3_cred)
...> |> Enum.take(1)
[
  {[1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 0, 2, 1], :IpAddress, [192, 0, 2, 1]}
]
```

## Installation

Add `:snmp_ex` to `mix.exs`:

```
defp deps do
  [ { :snmp_ex, "~> 0.2.0" } ]
end
```

Any of the following defaults may be overridden in your
`config.exs`.

```
config :snmp_ex,
  timeout: 5000,
  max_repetitions: 10,
  engine_discovery_timeout: 1000,
  mib_cache:      "priv/snmp/mibs",
  snmp_conf_dir:  "priv/snmp/conf",
  snmpm_conf_dir: "priv/snmp",
  snmpc_verbosity: "silence",
  mib_sources: ["/usr/share/snmp/mibs"]
```

`snmpc_verbosity` can be set to different values, see the [erlang docs](http://erlang.org/doc/man/snmpc.html) on which values you can use.

Finally, ensure the `:snmp` OTP application is available in
your development environment. Some Linux distributions, such
as CentOS, provide separate packages for individual OTP
services and tools. Check for `erlang-snmp` if this is a
concern. As for production, the release process will ensure
`:snmp` is automatically included in the resulting tarball.

## Why another wrapper?

`net-snmp-elixir` was my experimental hack to get something
that worked. I didn't expect it to become one of the top
Google results for "elixir snmp" but it is, which scares me.
Elixir may be the best language for network interaction in
existence, but we still need worthy SNMP support.

## Contributing

This project will accept (merge/rebase/squash) *all*
contributions. Contributions that break the build will be
reverted.

For details, please see [Why Optimistic Merging Works
Better](http://hintjens.com/blog:106).

## TODO

* ~~SNMPv3 USM~~ (AES requires patched OTP; see issue #6)
* ~~USM engine discovery~~
* SNMP tables
* ~~MIB name resolution~~
* Basic SNMP operations (~~GET~~, ~~GET-NEXT~~, ~~WALK~~, SET)
* Bulk SNMP operations
* Process management (~~supervision~~, `:snmpm` agents)
* Make it decent

