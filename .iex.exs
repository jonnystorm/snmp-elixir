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
    [%{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1]}]
  end

  def vb_ifx_name do
    [%{oid: [1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1]}]
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

  def bulkwalk_all do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: []}, [max_repetitions: 12])
    |> Enum.to_list()
  end

  def bulkwalk_test(varbinds) do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: varbinds}, [max_repetitions: 12])
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

  def bulkwalk_ifx_name do
    SNMP.bulkwalk(%{uri: uri(), credential: creds(), varbinds: vb_ifx_name()}, [max_repetitions: 12])
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

  def output_results(results) do
    results
    # |> Enum.map(fn {_, result} -> result end)
    |> Enum.each(fn result -> IO.puts(
      "#{format_oid(result.oid)} = #{result.type}: #{format_value(result.type, result.value)}") end)
    # |> Enum.each(fn result -> IO.inspect(result) end)
  end

  def format_oid(oid) when is_list(oid) do
    "." <> Enum.join(oid, ".")
  end

  def format_value(:"OCTET STRING", value) when is_binary(value) do
    # For potentially non-printable binaries, use inspect with limit: :infinity
    # to see the full binary representation
    inspect(value, limit: :infinity, printable_limit: :infinity)
  end

  # def format_value(:"OCTET STRING", value) when is_list(value) do
  #   # For char lists, try to convert to string when possible
  #   try do
  #     List.to_string(value)
  #   rescue
  #     _ -> inspect(value)
  #   end
  # end

  def format_value(type, value) when type == :"OBJECT IDENTIFIER" do
    format_oid(value)
  end

  #def format_value(:INTEGER, value), do: to_string(value)

  # def format_value(:"Counter32", value), do: to_string(value)
  # def format_value(:"Counter64", value), do: to_string(value)
  # def format_value(:"Gauge32", value), do: to_string(value)
  # def format_value(:"TimeTicks", value), do: to_string(value)

  # Fallback for all other types
  def format_value(_type, value) do
    inspect(value)
  end

  def bulkwalk_output do
    bulkwalk_test([%{oid: [1, 3, 6, 1]}])
    |> output_results()
  end
end
