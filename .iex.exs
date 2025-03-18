uri = URI.parse("snmp://127.0.0.1")
creds = SNMP.credential(%{version: :v2, community: "public"})
varbinds = [%{oid: [1, 3, 6, 1, 2, 1, 1]}]

defmodule Iex_SNMP do
  def uri do
    URI.parse("snmp://127.0.0.1")
  end

  def creds do
    SNMP.credential(%{version: :v2, community: "public"})
  end

  def vb_simple do
    [%{oid: [1, 3, 6, 1, 2, 1, 1]}]
  end

  def vb_if do
    [%{oid: [1, 3, 6, 1, 2, 1, 2, 2, 1]}]
  end

  def vb_ifx do
    [%{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1]}]
  end

  def get_request do
    SNMP.request(%{uri: uri(), credential: creds(), varbind: [system_varbinds()]})
  end

  def system_varbinds do
    [
      %{oid: [1, 3, 6, 1, 2, 1, 1, 1, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 1, 3, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 1, 4, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0]}
    ]
  end

  def be_specific do
    [
      %{oid: [1, 3, 6, 1, 2, 1, 1, 1, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 1, 3, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 1, 4, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 1, 5, 0]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 1]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1, 2]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 1]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6, 2]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10, 1]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10, 2]}
    ]
  end

  def ifx_name_octet_varbinds do
    [
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 6]},
      %{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 10]}
    ]
  end

  # Test bulkget in normal get operations with v2c
  def specific_get do
    SNMP.request(%{
      credential: creds(),
      uri: uri(),
      varbind: be_specific()
    })
  end

  # small request for perf testing
  def short_get(_) do
    SNMP.request(%{
        credential: creds(),
        uri: uri(),
        varbinds: system_varbinds()
      })
  end

  def perftest do
    1..500_000
    |> Task.async_stream(Iex_SNMP, :short_get, [], max_concurrency: 230)
    |> Enum.to_list()
  end

  def walk do
    %{uri: uri(), credential: creds(), varbinds: vb_ifx()} |> SNMP.walk()
  end

  def bulkwalk do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: vb_simple()}, [max_repetitions: 12])
    |> Enum.to_list()
  end

  def bulkwalk_if do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: vb_if()}, [max_repetitions: 12])
    |> Enum.to_list()
  end

  def bulkwalk_ifx do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: vb_ifx()}, [max_repetitions: 12])
    |> Enum.to_list()
  end

  def bulkwalk_mediumpacket do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: vb_ifx()}, [max_repetitions: 25])
    |> Enum.to_list()
  end

  def bulkwalk_bigpacket do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: vb_ifx()}, [max_repetitions: 50, timeout: 20000])
    |> Enum.to_list()
  end
end
