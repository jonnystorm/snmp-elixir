# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was
# not distributed with this file, You can obtain one at
# http://mozilla.org/MPL/2.0/.

defmodule SNMP do
  use Application

  @moduledoc """
  An SNMP client library for Elixir.
  """

  alias SNMP.{
    MIB,
    Utility,
    DiscoveryAgent
  }

  require Logger

  def start,
    do: start(:normal, [])

  def start(_type, args) do
    # snmpm configuration taken from
    # https://github.com/erlang/otp/blob/40de8cc4452dfdc5d390c93860870d4bf4605eb9/lib/snmp/src/manager/snmpm.erl#L156-L196

    mib_cache = Application.get_env(:snmp_ex, :mib_cache)

    snmp_conf_dir =
      Application.get_env(:snmp_ex, :snmp_conf_dir)

    snmpm_conf_dir =
      Application.get_env(:snmp_ex, :snmpm_conf_dir)

    _ = File.rm_rf!(mib_cache)
    _ = File.mkdir_p!(mib_cache)

    _ = File.rm_rf!(snmp_conf_dir)
    _ = File.mkdir_p!(snmp_conf_dir)

    _ = File.rm_rf!(snmpm_conf_dir)
    _ = File.mkdir_p!(snmpm_conf_dir)

    snmpm_conf_dir_erl =
      :binary.bin_to_list(snmpm_conf_dir)

    :ok =
      :snmp_config.write_manager_config(
        snmpm_conf_dir_erl,
        '',
        port: 5000,
        engine_id: 'mgrEngine',
        max_message_size: 484
      )

    snmpm_conf_dir =
      Application.get_env(:snmp_ex, :snmpm_conf_dir)
      |> :binary.bin_to_list()

    snmpm_opts = [
      versions: [:v1, :v2, :v3],
      config: [
        dir: snmpm_conf_dir,
        db_dir: snmpm_conf_dir
      ]
    ]

    children = [
      %{
        id: :snmpm_supervisor,
        start: {
          :snmpm_supervisor,
          :start_link,
          [:normal, snmpm_opts]
        }
      },
      %{
        id: SNMP.DiscoveryAgent,
        start: {
          SNMP.DiscoveryAgent,
          :start_link,
          []
        }
      }
    ]

    strategy = Keyword.get(args, :strategy, :one_for_one)

    sup_opts = [name: SNMP.Supervisor, strategy: strategy]

    {:ok, _} =
      result = Supervisor.start_link(children, sup_opts)

    user_mod = :snmpm_user_default

    :ok =
      :snmpm.register_user(__MODULE__, user_mod, self())

    _ = update_mib_cache()
    _ = load_cached_mibs()

    result
  end

  def get(
        object,
        agent,
        credential,
        options \\ []
      ) do
    perform_snmp_op(
      :get,
      object,
      agent,
      credential,
      options
    )
  end

  def get_next(
        object,
        agent,
        credential,
        options \\ []
      ) do
    perform_snmp_op(
      :get_next,
      object,
      agent,
      credential,
      options
    )
  end

  def walk(object, agent, credential, options \\ []) do
    [base_oid] = normalize_to_oid(object)

    {base_oid ++ [0], nil, nil}
    |> Stream.iterate(fn last_result ->
      {last_oid, _, _} = last_result

      last_oid
      |> get_next(agent, credential, options)
      |> List.first()
    end)
    |> Stream.take_while(fn {oid, _, _} ->
      List.starts_with?(oid, base_oid)
    end)
    |> Stream.drop(1)
  end

  def set(
        object,
        agent,
        credential,
        value,
        value_type,
        options \\ []
      ) do
    perform_snmp_op(
      :set,
      object,
      agent,
      credential,
      value,
      value_type,
      options
    )
  end

  @type mib_name :: String.t()
  @spec load_mib(mib_name) ::
          :ok
          | {:error, term}
  def load_mib(mib_name) do
    erl_mib_name = :binary.bin_to_list(mib_name)

    case :snmpm.load_mib(erl_mib_name) do
      :ok ->
        :ok

      {:error, reason} = error ->
        Logger.error(
          "Unable to load MIB #{inspect(mib_name)}: #{
            reason
          }"
        )

        error
    end
  end

  @spec load_mib!(mib_name) ::
          :ok
          | no_return
  def load_mib!(mib_name) when is_binary(mib_name) do
    if load_mib(mib_name) == :ok do
      :ok
    else
      raise "Unable to load mib #{inspect(mib_name)}"
    end
  end

  def resolve_object_name_to_oid(oid)
      when is_list(oid),
      do: oid

  def resolve_object_name_to_oid(name)
      when is_atom(name) do
    try do
      with {:ok, [oid]} <- :snmpm.name_to_oid(name),
           do: {:ok, oid}
    rescue
      e in ArgumentError ->
        Logger.warn(
          "Unhandled exception: did you forget to `SNMP.start`?"
        )

        reraise(e, System.stacktrace())
    end
  end

  defp find_mibs_recursive(dir),
    do: Utility.find_files_recursive(dir, ~r/\.(txt|mib)$/)

  defp change_dirname(path, new_dirname) do
    path
    |> Path.basename()
    |> Path.absname(new_dirname)
  end

  defp change_extension(path, new_extension),
    do: Path.rootname(path) <> new_extension

  defp mib_cache do
    :snmp_ex
    |> Application.get_env(:mib_cache)
    |> Path.expand()
  end

  defp mib_sources,
    do: Application.get_env(:snmp_ex, :mib_sources)

  defp update_mib_cache do
    cache_dir = mib_cache()

    _ =
      case File.exists?(cache_dir) do
        true ->
          _ = File.rm_rf!(cache_dir)
          _ = File.mkdir_p(cache_dir)

        false ->
          _ = File.mkdir_p(cache_dir)
      end

    _ =
      mib_sources()
      |> Stream.map(&Path.expand/1)
      |> Stream.flat_map(&find_mibs_recursive/1)
      |> Enum.uniq()
      |> Enum.map(fn source ->
        destination =
          source
          |> change_dirname(cache_dir)
          |> change_extension(".mib")

        File.cp(source, destination)
      end)

    MIB.compile_all(cache_dir)
  end

  defp load_cached_mibs do
    mib_cache()
    |> Utility.find_files_recursive(~r/\.bin$/)
    |> Enum.map(&load_mib/1)
  end

  defp timeout,
    do: Application.get_env(:snmp_ex, :timeout, 5000)

  defp delimiter_by_family(4), do: "."
  defp delimiter_by_family(6), do: ":"

  defp host_by_name(hostname) do
    result =
      hostname
      |> :binary.bin_to_list()
      |> :inet.gethostbyname()

    with {:ok, {_, _, _, _, family, [address | _]}} <-
           result do
      delimiter = delimiter_by_family(family)

      address_string =
        address
        |> Tuple.to_list()
        |> Enum.join(delimiter)

      {:ok, address_string}
    end
  end

  defp parse_ip(address) do
    case NetAddr.ip(address) do
      {:error, _} = error ->
        error

      netaddr ->
        {:ok, netaddr}
    end
  end

  defp resolve_host_to_netaddr(host) do
    with {:error, _} <- parse_ip(host),
         {:ok, ip} <- host_by_name(host),
         do: parse_ip(ip)
  end

  defp resolve_host_in_uri(uri) do
    with {:ok, netaddr} <-
           resolve_host_to_netaddr(uri.host) do
      ip_uri = %{uri | host: "#{NetAddr.address(netaddr)}"}

      {:ok, ip_uri}
    end
  end

  defp transport_from_netaddr(%NetAddr.IPv4{}),
    do: :transportDomainUdpIpv4

  defp transport_from_netaddr(%NetAddr.IPv6{}),
    do: :transportDomainUdpIpv6

  defp usm_user_config(credential, engine_id) do
    auth = credential.auth
    auth_pass = credential.auth_pass
    priv = credential.priv
    priv_pass = credential.priv_pass

    auth_key =
      if is_nil(auth) do
        []
      else
        auth
        |> :snmp.passwd2localized_key(
          auth_pass,
          engine_id
        )
      end

    priv_key =
      if is_nil(priv) do
        []
      else
        auth
        |> :snmp.passwd2localized_key(
          priv_pass,
          engine_id
        )
        |> Enum.slice(0..15)
      end

    [
      sec_name: credential.sec_name,
      auth: auth_proto_to_snmpm_auth(auth),
      auth_key: auth_key,
      priv: priv_proto_to_snmpm_auth(priv),
      priv_key: priv_key
    ]
  end

  defp register_usm_user(
         %{sec_model: :usm} = credential,
         engine_id
       ) do
    username = credential.sec_name
    config = usm_user_config(credential, engine_id)

    result =
      :snmpm.register_usm_user(engine_id, username, config)

    case result do
      :ok ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        Logger.error(
          "Unable to register USM user '#{username}': #{
            inspect(reason)
          }"
        )

        error
    end
  end

  defp register_usm_user(_credential, _engine_id),
    do: :ok

  defp register_agent(target, uri, credential, engine_id) do
    netaddr = NetAddr.ip(uri.host)
    cred_list = Map.to_list(credential)

    cred_keys = [
      :version,
      :sec_model,
      :community,
      :sec_level,
      :sec_name
    ]

    config =
      [
        engine_id: engine_id,
        address: NetAddr.netaddr_to_list(netaddr),
        port: uri.port || 161,
        tdomain: transport_from_netaddr(netaddr)
      ] ++ Keyword.take(cred_list, cred_keys)

    Logger.debug(
      "Will register agent #{uri} with target #{
        inspect(target)
      } and config #{inspect(config)}."
    )

    result =
      :snmpm.register_agent(__MODULE__, target, config)

    case result do
      :ok ->
        :ok

      {:error, {:already_registered, _}} ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        Logger.error(
          "Unable to register agent for #{uri}: #{
            inspect(reason)
          }"
        )

        error
    end
  end

  defp usm_stat_oid_to_name(oid) do
    case oid do
      [1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0] ->
        :usmStatsUnsupportedSecLevels

      [1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0] ->
        :usmStatsNotInTimeWindows

      [1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0] ->
        :usmStatsUnknownUserNames

      [1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0] ->
        :usmStatsUnknownEngineIDs

      [1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0] ->
        :usmStatsWrongDigests

      [1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0] ->
        :usmStatsDecryptionErrors
    end
  end

  defp groom_snmp_result(result) do
    sort_fun = fn {_, _, _, _, original_index} ->
      original_index
    end

    case result do
      {:ok, {:noError, 0, varbinds}, _} ->
        varbinds
        |> Enum.sort_by(sort_fun)
        |> Enum.map(fn {_, oid, type, value, _} ->
          {oid, type, value}
        end)

      {:error, {:invalid_oid, {:error, :not_found}}} ->
        Logger.error("Unknown OID")

        {:error, :unknown_oid}

      {:error, {:invalid_oid, {:ok, oid}}} ->
        oid_string = Enum.join(oid, ".")

        Logger.error("Invalid OID #{inspect(oid_string)}")

        {:error, {:invalid_oid, oid}}

      {:error, {:send_failed, _, reason}} ->
        Logger.error("Send failed: #{inspect(reason)}")

        {:error, reason}

      {:error, {:invalid_sec_info, _, snmp_info}} ->
        {_, _, [{:varbind, oid, _, _, _} | _]} = snmp_info

        name = usm_stat_oid_to_name(oid)

        Logger.error(
          "Received USM stats response: #{name}"
        )

        {:error, name}

      {:error, {:timeout, _}} ->
        Logger.error("Timeout!")

        {:error, :etimedout}

      other ->
        Logger.error(
          "Unexpected result: #{inspect(other)}"
        )

        {:error, :unknown_error}
    end
  end

  defp discover_engine_id(uri, target_name) do
    timeout =
      Application.get_env(
        :snmp_ex,
        :engine_discovery_timeout,
        1000
      )

    with {:error, _} <-
           :snmpm_config.get_agent_engine_id(target_name) do
      DiscoveryAgent.discover_engine_id(
        uri,
        timeout: timeout
      )
    end
  end

  defp warmup_engine_boots_and_engine_time(
         engine_id,
         target_name
       ) do
    {:ok, engine_boots} =
      :snmpm_config.get_usm_eboots(engine_id)

    if engine_boots == 0 do
      # warm-up to update the engineBoots and engineTime in
      # SNMPM

      :snmpm.sync_get(__MODULE__, target_name, [], 2000)
    end

    :ok
  end

  defp sha_sum(string) when is_binary(string),
    do: :crypto.hash(:sha, string)

  defp is_dotted_decimal(string)
       when is_binary(string),
       do: string =~ ~r/^\.?\d(\.\d)+$/

  defp is_dotted_decimal(_string),
    do: false

  def normalize_to_oid(object) do
    cond do
      :snmp_misc.is_oid(object) ->
        [object]

      is_dotted_decimal(object) ->
        [string_oid_to_list(object)]

      is_atom(object) ->
        {:ok, oid} = resolve_object_name_to_oid(object)
        [oid]

      true ->
        atom = String.to_atom(object)
        {:ok, oid} = resolve_object_name_to_oid(atom)

        [oid]
    end
  end

  defp normalize_to_uri(%URI{} = uri),
    do: uri

  defp normalize_to_uri(agent) when is_binary(agent) do
    cond do
      agent =~ ~r|^snmp://| ->
        URI.parse(agent)

      true ->
        URI.parse("snmp://#{agent}")
    end
  end

  defp normalize_to_snmp_value_type("i"), do: {:ok, :i}

  defp normalize_to_snmp_value_type("integer"),
    do: {:ok, :i}

  defp normalize_to_snmp_value_type("u"), do: {:ok, :u}

  defp normalize_to_snmp_value_type("unsigned"),
    do: {:ok, :u}

  defp normalize_to_snmp_value_type("t"), do: {:ok, :t}

  defp normalize_to_snmp_value_type("timeticks"),
    do: {:ok, :t}

  defp normalize_to_snmp_value_type("a"), do: {:ok, :a}

  defp normalize_to_snmp_value_type("ipaddress"),
    do: {:ok, :a}

  defp normalize_to_snmp_value_type("o"), do: {:ok, :o}

  defp normalize_to_snmp_value_type("object"),
    do: {:ok, :o}

  defp normalize_to_snmp_value_type("s"), do: {:ok, :s}

  defp normalize_to_snmp_value_type("string"),
    do: {:ok, :s}

  defp normalize_to_snmp_value_type("x"), do: {:ok, :x}
  defp normalize_to_snmp_value_type("hex"), do: {:ok, :x}
  defp normalize_to_snmp_value_type("d"), do: {:ok, :d}

  defp normalize_to_snmp_value_type("decimal"),
    do: {:ok, :d}

  defp normalize_to_snmp_value_type("b"), do: {:ok, :b}
  defp normalize_to_snmp_value_type("bits"), do: {:ok, :b}

  defp normalize_to_snmp_value_type(type) do
    Logger.error("Invalid SNMP ValueType #{type}")
    {:error, "#{type} not a known SNMP ValueType"}
  end

  defp perform_snmp_op(
         op,
         object,
         agent,
         credential,
         options
       ) do
    [oid, target] =
      prepare_perform_snmp_op(
        object,
        agent,
        credential,
        options
      )

    options = Keyword.put(options, :timeout, timeout())

    result =
      case op do
        :get ->
          :snmpm.sync_get2(
            __MODULE__,
            target,
            oid,
            options
          )

        :get_next ->
          :snmpm.sync_get_next2(
            __MODULE__,
            target,
            oid,
            options
          )
      end

    groom_snmp_result(result)
  end

  defp perform_snmp_op(
         :set,
         object,
         agent,
         credential,
         value,
         value_type,
         options
       ) do
    [oid, target] =
      prepare_perform_snmp_op(
        object,
        agent,
        credential,
        options
      )

    with {:ok, snmp_value_type} <-
           normalize_to_snmp_value_type(value_type) do
      var_and_val = [{oid, snmp_value_type, value}]

      result =
        :snmpm.sync_set2(
          __MODULE__,
          target,
          var_and_val,
          timeout: timeout()
        )

      groom_snmp_result(result)
    end
  end

  defp prepare_perform_snmp_op(
         object,
         agent,
         credential,
         options
       ) do
    with {:ok, uri} <-
           agent
           |> normalize_to_uri
           |> resolve_host_in_uri do
      oid = normalize_to_oid(object)
      target = generate_target_name(uri, credential)

      discover_fun = fn ->
        case discover_engine_id(uri, target) do
          {:ok, eid} -> :binary.list_to_bin(eid)
          {:error, _} -> Utility.local_engine_id()
        end
      end

      engine_id =
        options
        |> Keyword.get_lazy(:engine_id, discover_fun)
        |> :binary.bin_to_list()

      :ok = register_usm_user(credential, engine_id)

      :ok =
        register_agent(
          target,
          uri,
          credential,
          engine_id
        )

      :ok =
        warmup_engine_boots_and_engine_time(
          engine_id,
          target
        )

      [oid, target]
    end
  end

  defp generate_target_name(uri, credential) do
    # Make a concise target name that is unique per host,
    # per credential

    "#{uri}#{inspect(credential)}"
    |> sha_sum
    |> :binary.bin_to_list()
  end

  defp auth_proto_to_snmpm_auth(:md5),
    do: :usmHMACMD5AuthProtocol

  defp auth_proto_to_snmpm_auth(:sha),
    do: :usmHMACSHAAuthProtocol

  defp auth_proto_to_snmpm_auth(_), do: :usmNoAuthProtocol

  defp priv_proto_to_snmpm_auth(:des),
    do: :usmDESPrivProtocol

  defp priv_proto_to_snmpm_auth(:aes),
    do: :usmAesCfb128Protocol

  defp priv_proto_to_snmpm_auth(_), do: :usmNoPrivProtocol

  @doc """
  Converts `oid` to dot-delimited string.

  ## Example

      iex> SNMP.list_oid_to_string([1,3,6,1,2,1,1,5,0])
      "1.3.6.1.2.1.1.5.0"

  """
  @spec list_oid_to_string([non_neg_integer]) ::
          String.t()
          | no_return
  def list_oid_to_string(oid) when is_list(oid),
    do: Enum.join(oid, ".")

  @doc """
  Converts dot-delimited `oid` string to list.

  ## Example

      iex> SNMP.string_oid_to_list("1.3.6.1.2.1.1.5.0")
      [1,3,6,1,2,1,1,5,0]

  """
  @spec string_oid_to_list(String.t()) ::
          [non_neg_integer]
          | no_return
  def string_oid_to_list(oid) when is_binary(oid) do
    oid
    |> String.split(".", trim: true)
    |> Enum.map(&String.to_integer/1)
  end
end
