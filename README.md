# snmp-elixir

[![Build Status](https://gitlab.com/jonnystorm/snmp-elixir/badges/master/pipeline.svg)](https://gitlab.com/jonnystorm/snmp-elixir/commits/master)

An SNMP client library for Elixir.

This is my effort to replace the terrible but useful
[net-snmp-elixir](https://gitlab.com/jonnystorm/net-snmp-elixir) with a
facile Elixir wrapper for OTP's harrowing SNMP API.

Many thanks to Dave Martin for his
[post](https://groups.google.com/forum/#!topic/elixir-lang-talk/lGWGXFoUVvc),
without which I may never have bothered returning to this problem.

## Usage in CLI
```elixir
iex> SNMP.Supervisor.start_link
iex> v2_cred = SNMP.credential [:v2c, "public"]
%SNMP.CommunityCredential{
  community: 'public',
  sec_model: :v2c,
  version: :v2
}
iex>
iex> {:ok, base_oid} = SNMP.resolve_object_name_to_oid :sysName
{:ok, [1, 3, 6, 1, 2, 1, 1, 5]}
iex>
iex> SNMP.get base_oid ++ [0], "an-snmp-host.local", v2_cred
[
  {[1, 3, 6, 1, 2, 1, 1, 5, 0], :"OCTET STRING", 'an-snmp-host'}
]
iex>
iex> v3_cred = SNMP.credential [:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass",]
%SNMP.USMCredential{
  auth: :sha,
  auth_pass: 'neij44N7cczEFDBzhSwQ',
  priv: :aes,
  priv_pass: '2Q5ZBXHhjGpWlVdYQxmO',
  sec_level: :authPriv,
  sec_model: :usm,
  sec_name: 'nms',
  version: :v3
}
iex> SNMP.walk("ipAddrTable", "an-snmp-host.local", v3_cred) |> Enum.take(1)
[
  {[1, 3, 6, 1, 2, 1, 4, 20, 1, 1, 192, 0, 2, 1], :IpAddress, [192, 0, 2, 1]}
]
```

## Supervisor
You now can add `SNMP.Supervisor` as a child in your application supervisor tree! The SNMP module is now a GenServer, where it could previously be started by using `SNMP.start` you now should use `SNMP.Supervisor.start_link`

## Installation
Add `snmp_ex` to your list of dependencies in you `mix.exs` file. Then run `mix deps.get`;)
```
defp deps do
  [
    {:snmp_ex, git: "https://github.com/jonnystorm/snmp-elixir.git"}
  ]
end
```

Add to your `/config/config.exs` file:
```
config :snmp_ex,
  timeout: 5000,
  max_repetitions: 10
```

You may also want to add `SNMP` to your supervisor tree in your `application.ex` file (see below for an example):
```
def start(_type, _args) do
  Logger.debug("starting application....")

  children = [
    SNMP.Supervisor,
  ]

  Supervisor.start_link(children, strategy: :one_for_one)
end
```

## Why another wrapper?

`net-snmp-elixir` was my experimental hack to get something that worked.
I didn't expect it to become one of the top Google results for "elixir snmp"
but it is, which scares me. Elixir may be the best language for network
interaction in existence, but we still need worthy SNMP support.

## Contributing

This project will accept (merge/rebase/squash) *all* contributions.
Contributions that break the build will be reverted.

For details, please see [Why Optimistic Merging Works Better](http://hintjens.com/blog:106).

## TODO

* ~~SNMPv3 USM~~ (requires patched OTP; see issue #6)
* ~~USM engine discovery~~
* SNMP tables
* ~~MIB name resolution~~
* Basic SNMP operations (~~GET~~, ~~GET-NEXT~~, ~~WALK~~, SET)
* Bulk SNMP operations
* ~~Process management (GenServerize)~~
* Make it decent

