# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SNMP do
  @moduledoc """
  An SNMP client library for Elixir.
  """

  alias SNMP.{
    MIB,
    Utility,
    CommunityCredential,
    USMCredential,
    DiscoveryAgent
  }

  require Logger

  @type snmp_credential :: CommunityCredential.t
                         | USMCredential.t

  defmodule CommunityCredential do
    defstruct [
      :version,
      :sec_model,
      :community,
    ]

    @type t :: %__MODULE__{
      version:   :v1 | :v2,
      sec_model: :v1 | :v2c,
      community: [byte],
    }
  end

  defmodule USMCredential do
    defstruct [
        version: :v3,
      sec_model: :usm,
      sec_level: nil,
       sec_name: [],
           auth: nil,
      auth_pass: nil,
           priv: nil,
      priv_pass: nil,
    ]

    @type t :: %__MODULE__{
        version: :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv
               | :authNoPriv
               | :authPriv,
       sec_name: [byte],
           auth: nil | :md5 | :sha,
      auth_pass: nil | [byte],
           priv: nil | :des | :aes,
      priv_pass: nil | [byte],
    }
  end

  defp find_mibs_recursive(dir),
    do: Utility.find_files_recursive(dir, ~r/\.(txt|mib)$/)

  defp change_dirname(path, new_dirname) do
    path
    |> Path.basename
    |> Path.absname(new_dirname)
  end

  defp change_extension(path, new_extension),
    do: Path.rootname(path) <> new_extension

  defp mib_cache,
    do: Path.expand Application.get_env(:snmp_ex, :mib_cache)

  defp mib_sources,
    do: Application.get_env(:snmp_ex, :mib_sources)

  defp update_mib_cache do
    cache_dir = mib_cache()
    source_dirs = mib_sources()

    _ = File.mkdir_p cache_dir

    _ =
      source_dirs
      |> Stream.map(&Path.expand/1)
      |> Stream.flat_map(&find_mibs_recursive/1)
      |> Enum.uniq
      |> Enum.map(fn source ->
        destination =
          source
          |> change_dirname(cache_dir)
          |> change_extension(".mib")

        :ok = File.cp!(source, destination)
      end)

    _ = MIB.compile_all cache_dir
  end

  defp load_cached_mibs do
    mib_cache()
    |> Utility.find_files_recursive(~r/\.bin$/)
    |> Enum.map(&load_mib/1)
  end

  def start do
    :ok = :snmpm.start
    {:ok, _pid} = DiscoveryAgent.start_link
    :ok = :snmpm.register_user(__MODULE__, :snmpm_user_default, self())
    _ = update_mib_cache()
    _ = load_cached_mibs()
    :ok
  end

  defp get_timeout,
    do: Application.get_env(:snmp_ex, :timeout)

  defp get_max_repetitions,
    do: Application.get_env(:snmp_ex, :max_repetitions)

  defp get_delimiter_by_family(4), do: "."
  defp get_delimiter_by_family(6), do: ":"

  defp get_host_by_name(hostname) do
    result = :inet.gethostbyname :binary.bin_to_list(hostname)

    with {:ok, {_, _, _, _, family, [address|_]}} <- result
    do
      delimiter = get_delimiter_by_family(family)
      address_string =
        address
        |> Tuple.to_list
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
         {:ok,   ip} <- get_host_by_name(host),
         {:error, _} <- parse_ip(ip)
    do
      :ok = Logger.error("Unable to resolve host #{inspect host}")

      {:error, :einval}
    end
  end

  defp get_transport_from_netaddr(%NetAddr.IPv4{}),
    do: :transportDomainUdpIpv4
  defp get_transport_from_netaddr(%NetAddr.IPv6{}),
    do: :transportDomainUdpIpv6

  defp get_usm_user_config(credential, engine_id) do
    auth      = credential.auth
    auth_pass = credential.auth_pass
    priv      = credential.priv
    priv_pass = credential.priv_pass

    auth_key  =
      if is_nil auth do
        []
      else
        auth
        |> :snmp.passwd2localized_key(auth_pass, engine_id)
      end

    priv_key  =
      if is_nil priv do
        []
      else
        auth
        |> :snmp.passwd2localized_key(priv_pass, engine_id)
        |> Enum.slice(0..15)
      end

    [ sec_name: credential.sec_name,
      auth:     auth_proto_to_snmpm_auth(auth),
      auth_key: auth_key,
      priv:     priv_proto_to_snmpm_auth(priv),
      priv_key: priv_key,
    ]
  end

  defp register_usm_user(%{sec_model: :usm} = credential, engine_id) do
    username = credential.sec_name
    config = get_usm_user_config(credential, engine_id)

    case :snmpm.register_usm_user(engine_id, username, config) do
      :ok ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to register USM user '#{username}': #{inspect reason}")

        error
    end
  end

  defp register_usm_user(_credential, _engine_id), do: :ok

  defp register_agent(target, uri, netaddr, credential, engine_id) do
    cred_list = Map.to_list credential
    cred_keys = [:version, :sec_model, :community, :sec_level, :sec_name]
    config =
      [ engine_id: engine_id,
          address: NetAddr.netaddr_to_list(netaddr),
             port: uri.port || 161,
          tdomain: get_transport_from_netaddr(netaddr),
      ] ++ Keyword.take(cred_list, cred_keys)

    :ok = Logger.debug("Will register agent #{uri} with target #{inspect target} and config #{inspect config}.")

    case :snmpm.register_agent(__MODULE__, target, config) do
      :ok ->
        :ok
      {:error, {:already_registered, _}} ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to register agent for #{uri}: #{inspect reason}")

        error
    end
  end

  defp usm_stat_oid_to_name(oid) do
    case oid do
      [1,3,6,1,6,3,15,1,1,1,0] -> :usmStatsUnsupportedSecLevels
      [1,3,6,1,6,3,15,1,1,2,0] -> :usmStatsNotInTimeWindows
      [1,3,6,1,6,3,15,1,1,3,0] -> :usmStatsUnknownUserNames
      [1,3,6,1,6,3,15,1,1,4,0] -> :usmStatsUnknownEngineIDs
      [1,3,6,1,6,3,15,1,1,5,0] -> :usmStatsWrongDigests
      [1,3,6,1,6,3,15,1,1,6,0] -> :usmStatsDecryptionErrors
    end
  end

  defp groom_snmp_result(result) do
    case result do
      {:ok, {:noError, 0, varbinds}, _} ->
        varbinds
        |> Enum.sort_by(fn {_, _, _, _, original_index} -> original_index end)
        |> Enum.map(fn {_, oid, type, value, _} ->
          {oid, type, value}
        end)

      {:error, {:invalid_oid, {:error, :not_found}}} ->
        :ok = Logger.error("Unknown OID")

        {:error, :unknown_oid}

      {:error, {:invalid_oid, {:ok, oid}}} ->
        oid_string = Enum.join(oid, ".")

        :ok = Logger.error("Invalid OID #{inspect oid_string}")

        {:error, {:invalid_oid, oid}}

      {:error, {:send_failed, _, reason}} ->
        :ok = Logger.error("Send failed: #{inspect reason}")

        {:error, reason}

      {:error, {:invalid_sec_info, _, snmp_info}} ->
        {_, _, [{:varbind, oid, _, _, _}|_]} = snmp_info

        name = usm_stat_oid_to_name(oid)

        :ok = Logger.error("Received USM stats response: #{name}")

        {:error, name}

      {:error, {:timeout, _}} ->
        :ok = Logger.error("Timeout!")

        {:error, :etimedout}

      other ->
        :ok = Logger.error("Unexpected result: #{inspect other}")

        {:error, :unknown_error}
    end
  end

  defp discover_engine_id(uri, netaddr, target_name) do
    engine_id =
      case :snmpm_config.get_agent_engine_id(target_name) do
          {:ok, engine_id} -> engine_id
          _ ->
            DiscoveryAgent.find_engine_id(netaddr.address, port: uri.port)
      end
    :binary.list_to_bin(engine_id)
  end

  defp warmup_engine_boots_and_engine_time(engine_id, target_name) do
    {:ok, engine_boots} = :snmpm_config.get_usm_eboots(engine_id)
    if engine_boots == 0 do
      :snmpm.sync_get(__MODULE__, target_name, [], 2000) #warm-up to update the engineBoots and engineTime in SNMPM.
    end
    :ok
  end

  defp sha_sum(string) when is_binary(string),
    do: :crypto.hash(:sha, string)

  defp is_dotted_decimal(string),
    do: string =~ ~r/^\.?\d(\.\d)+$/

  defp normalize_to_oids([[]]),
    do: []

  defp normalize_to_oids(objects) do
    objects
    |> Enum.reduce([], fn(object, acc) ->
      cond do
        :snmp_misc.is_oid(object) ->
          [object|acc]

        is_dotted_decimal(object) ->
          [string_oid_to_list(object)|acc]

        true ->
          atom = String.to_atom object

          [resolve_object_name_to_oid(atom)|acc]
      end
    end)
    |> Enum.reverse
  end

  defp normalize_to_uri(%URI{} = uri), do: uri

  defp normalize_to_uri(agent) when is_binary agent do
    cond do
      agent =~ ~r|^snmp://| ->
        URI.parse(agent)

      true ->
        URI.parse("snmp://#{agent}")
    end
  end

  defp _perform_snmp_op(op, oids, target, context, timeout) do
    case op do
      :get ->
        :snmpm.sync_get(__MODULE__, target, context, oids, timeout)
    end
  end

  defp perform_snmp_op(op, objects, agent, credential, options) do
    uri  = normalize_to_uri(agent)
    {:ok, netaddr} = resolve_host_to_netaddr(uri.host)
    oids = normalize_to_oids(objects)

    target      = generate_target_name(uri, credential)
    erl_context = :binary.bin_to_list Keyword.get(options, :context, "")
    engine_id   =
      options
      |> Keyword.get(:engine_id, discover_engine_id(uri, netaddr, target))
      |> :binary.bin_to_list

    with :ok <- register_usm_user(credential, engine_id),
         :ok <- register_agent(target, uri, netaddr, credential, engine_id),
         :ok <- warmup_engine_boots_and_engine_time(engine_id, target)
    do
      op
      |> _perform_snmp_op(oids, target, erl_context, get_timeout())
      |> groom_snmp_result
    end
  end

  defp generate_target_name(uri, credential) do
    # Make a concise target name that is unique per host, per credential
    :binary.bin_to_list sha_sum("#{uri}#{inspect credential}")
  end

  def get(objects, agent, credential, options \\ [])

  def get([h|_] = objects, agent, credential, options)
      when is_list(h)
        or is_binary(h),
    do: perform_snmp_op(:get, objects, agent, credential, options)

  def get(object, agent, credential, options),
    do: get([object], agent, credential, options)

  @type mib_name :: String.t

  @spec load_mib(mib_name) :: :ok | {:error, term}
  def load_mib(mib_name) do
    erl_mib_name = :binary.bin_to_list mib_name

    case :snmpm.load_mib(erl_mib_name) do
      :ok ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to load MIB #{inspect mib_name}: #{reason}")

        error
    end
  end

  @spec load_mib!(mib_name) :: :ok | no_return
  def load_mib!(mib_name) when is_binary(mib_name) do
    if load_mib(mib_name) == :ok do
      :ok
    else
      raise "Unable to load mib #{inspect mib_name}"
    end
  end

  def resolve_object_name_to_oid(name) when is_atom(name) do
    try do
      with {:ok, [oid]} <- :snmpm.name_to_oid(name),
        do: {:ok, oid}

    rescue
      e in ArgumentError ->
        :ok = Logger.warn("Unhandled exception: did you forget to `SNMP.start`?")

        reraise e, System.stacktrace
    end
  end

  @doc """
  Returns a keyword list containing the given SNMPv1/2c/3 credentials.

  ## Example

      iex> SNMP.credential([:v1, "public"])
      %SNMP.CommunityCredential{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.credential([:v2c, "public"])
      %SNMP.CommunityCredential{version: :v2, sec_model: :v2c, community: 'public'}

      iex> SNMP.credential([:v3, :no_auth_no_priv, "user"])
      %SNMP.USMCredential{sec_level: :noAuthNoPriv, sec_name:  'user'}

      iex> SNMP.credential([:v3, :auth_no_priv, "user", :md5, "authpass"])
      %SNMP.USMCredential{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
      }

      iex> SNMP.credential([:v3, :auth_no_priv, "user", :sha, "authpass"])
      %SNMP.USMCredential{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass"])
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass"])
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass"])
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"])
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

  """
  @spec credential([atom | String.t])
    :: snmp_credential | no_return
  def credential(args) when is_list args do
    case args do
      [:v1, _] ->
        apply(&credential/2, args)

      [:v2c, _] ->
        apply(&credential/2, args)

      [:v3, :no_auth_no_priv, _] ->
        apply(&credential/3, args)

      [:v3, :auth_no_priv, _, _, _] ->
        apply(&credential/5, args)

      [:v3, :auth_priv, _, _, _, _, _] ->
        apply(&credential/7, args)
    end
  end

  @doc """
  Returns a keyword list containing the given SNMPv1/2c community.

  ## Example

      iex> SNMP.credential(:v1, "public")
      %SNMP.CommunityCredential{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.credential(:v2c, "public")
      %SNMP.CommunityCredential{version: :v2, sec_model: :v2c, community: 'public'}

  """
  @spec credential(:v1 | :v2c, String.t)
    :: snmp_credential | no_return
  def credential(version, community)

  def credential(:v1, community) do
    %CommunityCredential{
      version:   :v1,
      sec_model: :v1,
      community: :binary.bin_to_list(community),
    }
  end

  def credential(:v2c, community) do
    %CommunityCredential{
      version:   :v2,
      sec_model: :v2c,
      community: :binary.bin_to_list(community),
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3 noAuthNoPriv credentials.

  ## Example

      iex> SNMP.credential(:v3, :no_auth_no_priv, "user")
      %SNMP.USMCredential{sec_level: :noAuthNoPriv, sec_name: 'user'}

  """
  @spec credential(:v3, :no_auth_no_priv, String.t)
    :: snmp_credential | no_return
  def credential(version, sec_level, sec_name)

  def credential(:v3, :no_auth_no_priv, sec_name),
    do: %USMCredential{
      sec_level: :noAuthNoPriv,
      sec_name: :binary.bin_to_list(sec_name)
    }

  @doc """
  Returns a keyword list containing the given SNMPv3 authNoPriv credentials.

  ## Example

      iex> SNMP.credential(:v3, :auth_no_priv, "user", :md5, "authpass")
      %SNMP.USMCredential{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
      }

      iex> SNMP.credential(:v3, :auth_no_priv, "user", :sha, "authpass")
      %SNMP.USMCredential{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
      }

  """
  @spec credential(:v3, :auth_no_priv, String.t, :md5|:sha, String.t)
    :: snmp_credential | no_return

  def credential(version, sec_level, sec_name, auth_proto, auth_pass)

  def credential(:v3, :auth_no_priv, sec_name, auth_proto, auth_pass)
      when auth_proto in [:md5, :sha]
  do
    %USMCredential{
      sec_level: :authNoPriv,
      sec_name:  :binary.bin_to_list(sec_name),
      auth:      auth_proto,
      auth_pass: :binary.bin_to_list(auth_pass),
    }
  end

  defp auth_proto_to_snmpm_auth(:md5), do: :usmHMACMD5AuthProtocol
  defp auth_proto_to_snmpm_auth(:sha), do: :usmHMACSHAAuthProtocol
  defp auth_proto_to_snmpm_auth(_),    do: :usmNoAuthProtocol

  defp priv_proto_to_snmpm_auth(:des), do: :usmDESPrivProtocol
  defp priv_proto_to_snmpm_auth(:aes), do: :usmAesCfb128Protocol
  defp priv_proto_to_snmpm_auth(_),    do: :usmNoPrivProtocol

  @doc """
  Returns `t:snmp_credential/0` containing the given SNMPv3 authPriv credentials.

  ## Examples

      iex> SNMP.credential(:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass")
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass")
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass")
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass")
      %SNMP.USMCredential{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

  """
  @spec credential(:v3, :auth_priv, String.t, :md5|:sha, String.t, :des|:aes, String.t)
    :: snmp_credential | no_return
  def credential(version, sec_level, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)

  def credential(:v3, :auth_priv, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)
      when auth_proto in [:md5, :sha]
       and priv_proto in [:des, :aes]
  do
    # http://erlang.org/doc/man/snmpm.html#register_usm_user-3
    %USMCredential{
      sec_level: :authPriv,
      sec_name:  :binary.bin_to_list(sec_name),
      auth:      auth_proto,
      auth_pass: :binary.bin_to_list(auth_pass),
      priv:      priv_proto,
      priv_pass: :binary.bin_to_list(priv_pass),
    }
  end

  @doc """
  Converts `oid` to dot-delimited string.

  ## Example

      iex> SNMP.list_oid_to_string([1,3,6,1,2,1,1,5,0])
      "1.3.6.1.2.1.1.5.0"

  """
  @spec list_oid_to_string([non_neg_integer]) :: String.t | no_return
  def list_oid_to_string(oid) when is_list(oid),
    do: Enum.join(oid, ".")

  @doc """
  Converts dot-delimited `oid` string to list.

  ## Example

      iex> SNMP.string_oid_to_list("1.3.6.1.2.1.1.5.0")
      [1,3,6,1,2,1,1,5,0]

  """
  @spec string_oid_to_list(String.t) :: [non_neg_integer] | no_return
  def string_oid_to_list(oid) when is_binary oid do
    oid
    |> String.split(".", [trim: true])
    |> Enum.map(&String.to_integer/1)
  end
end
