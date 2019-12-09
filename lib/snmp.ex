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
    CommunityCredential,
    USMCredential,
    DiscoveryAgent
  }

  require Logger

  @type snmp_credential
    :: CommunityCredential.t()
     | USMCredential.t()

  defmodule CommunityCredential do
    defstruct [
      version: :v1,
      sec_model: :v1,
      community: nil,
    ]

    @type t ::
      %__MODULE__{
        version:   :v1 | :v2,
        sec_model: :v1 | :v2c,
        community: [byte],
      }
  end

  defmodule USMCredential do
    defstruct [
      version:   :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv,
      sec_name:  [],
      auth:      :usmNoAuthProtocol,
      auth_pass: nil,
      priv:      :usmNoPrivProtocol,
      priv_pass: nil,
    ]

    @type t ::
      %__MODULE__{
        version:   :v3,
        sec_model: :usm,
        sec_level:
            :noAuthNoPriv
          | :authNoPriv
          | :authPriv,
        sec_name:  [byte],
        auth:
            :usmNoAuthProtocol
          | :usmHMACMD5AuthProtocol
          | :usmHMACSHAAuthProtocol,
        auth_pass: nil | [byte],
        priv:
            :usmNoPrivProtocol
          | :usmDESPrivProtocol
          | :usmAesCfb128Protocol,
        priv_pass: nil | [byte]
      }
  end

  def start,
    do: start(:normal, [])

  def start(_type, args) do
    # snmpm configuration taken from
    # https://github.com/erlang/otp/blob/40de8cc4452dfdc5d390c93860870d4bf4605eb9/lib/snmp/src/manager/snmpm.erl#L156-L196

    mib_cache =
      Application.get_env(:snmp_ex, :mib_cache)

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

    snmpm_opts =
      [ versions: [:v1, :v2, :v3],
        config: [
          dir:    snmpm_conf_dir,
          db_dir: snmpm_conf_dir,
        ],
      ]

    children =
      [ %{id: :snmpm_supervisor,
          start: {
            :snmpm_supervisor,
            :start_link,
            [:normal, snmpm_opts]
          },
        },
        %{id: SNMP.DiscoveryAgent,
          start: {
            SNMP.DiscoveryAgent,
            :start_link,
            []
          },
        },
      ]

    strategy =
      Keyword.get(args, :strategy, :one_for_one)

    sup_opts =
      [ name:     SNMP.Supervisor,
        strategy: strategy,
      ]

    {:ok, _} = result =
      Supervisor.start_link(children, sup_opts)

    user_mod = :snmpm_user_default

    :ok =
      :snmpm.register_user(__MODULE__, user_mod, self())

    _ = update_mib_cache()
    _ = load_cached_mibs()

    result
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

  defp get_timeout,
    do: Application.get_env(:snmp_ex, :timeout)

  defp get_max_repetitions,
    do: Application.get_env(:snmp_ex, :max_repetitions)

  defp get_delimiter_by_family(4), do: "."
  defp get_delimiter_by_family(6), do: ":"

  defp get_host_by_name(hostname) do
    result =
      hostname
      |> :binary.bin_to_list()
      |> :inet.gethostbyname()

    with {:ok, {_, _, _, _, family, [address | _]}}
           <- result
    do
      delimiter = get_delimiter_by_family(family)

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
         {:ok, ip} <- get_host_by_name(host),
      do: parse_ip(ip)
  end

  defp resolve_host_in_uri(uri) do
    with {:ok, netaddr}
           <- resolve_host_to_netaddr(uri.host)
    do
      ip_uri =
        %{uri |
          host: "#{NetAddr.address(netaddr)}"
        }

      {:ok, ip_uri}
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

    hash_algo =
      case auth do
        :usmNoAuthProtocol      -> nil
        :usmHMACMD5AuthProtocol -> :md5
        :usmHMACSHAAuthProtocol -> :sha
      end

    auth_key =
      if is_nil(auth_pass) do
        []
      else
        hash_algo
        |> :snmp.passwd2localized_key(auth_pass, engine_id)
      end

    priv_key =
      if is_nil(priv_pass) do
        []
      else
        hash_algo
        |> :snmp.passwd2localized_key(priv_pass, engine_id)
        |> Enum.slice(0..15)
      end

    [ sec_name: credential.sec_name,
      auth:     auth,
      auth_key: auth_key,
      priv:     priv,
      priv_key: priv_key
    ]
  end

  defp register_usm_user(
    %{sec_model: :usm} = credential,
    engine_id
  ) do
    username = credential.sec_name
    config   =
      get_usm_user_config(credential, engine_id)

    result =
      :snmpm.register_usm_user(engine_id, username, config)

    case result do
      :ok ->
        :ok

      {:error, {:already_registered, _, _}} ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to register USM user '#{username}': #{inspect(reason)}")

        error
    end
  end

  defp register_usm_user(_credential, _engine_id),
    do: :ok

  defp register_agent(target, uri, credential, engine_id)
  do
    netaddr   = NetAddr.ip(uri.host)
    cred_list = Map.to_list(credential)
    cred_keys =
      [ :version,
        :sec_model,
        :community,
        :sec_level,
        :sec_name
      ]

    config =
      [ engine_id: engine_id,
        address:   NetAddr.netaddr_to_list(netaddr),
        port:      uri.port || 161,
        tdomain:   get_transport_from_netaddr(netaddr)
      ] ++ Keyword.take(cred_list, cred_keys)

    :ok = Logger.debug("Will register agent #{uri} with target #{inspect(target)} and config #{inspect(config)}.")

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
        :ok = Logger.error("Unable to register agent for #{uri}: #{inspect(reason)}")

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

  defp groom_erl_varbind(
    %{type: t, value: v} = varbind
  ) do
    new_v =
      case t do
        :"OCTET STRING" -> :binary.list_to_bin(v)
        _               -> v
      end

    %{varbind|value: new_v}
  end

  defp groom_snmp_result(result) do
    sort_fun =
      fn {_, _, _, _, original_index} ->
        original_index
      end

    case result do
      {:ok, {reply, err_index, varbinds}, _} ->
        if {reply, err_index} == {:noError, 0} do
          result =
            varbinds
            |> Enum.sort_by(sort_fun)
            |> Enum.map(fn {_, oid, type, value, _} ->
              %{oid: oid, type: type, value: value}
              |> groom_erl_varbind
            end)

          {:ok, result}
        else
          {_, oid, type, value, _} =
            Enum.at(varbinds, err_index - 1)

          varbind =
            %{oid: oid, type: type, value: value}
            |> groom_erl_varbind

          {:error, {reply, varbind}}
        end

      {:error, {:invalid_oid, {:error, :not_found}}} ->
        :ok = Logger.error("Unknown OID")

        {:error, :unknown_oid}

      {:error, {:invalid_oid, {:ok, oid}}} ->
        oid_string = Enum.join(oid, ".")

        :ok = Logger.error("Invalid OID #{inspect(oid_string)}")

        {:error, {:invalid_oid, oid}}

      {:error, {:send_failed, _, reason}} ->
        :ok = Logger.error("Send failed: #{inspect(reason)}")

        {:error, reason}

      {:error, {:invalid_sec_info, _, snmp_info}} ->
        {_, _, [{:varbind, oid, _, _, _} | _]} = snmp_info

        name = usm_stat_oid_to_name(oid)

        :ok = Logger.error("Received USM stats response: #{name}")

        {:error, name}

      {:error, {:timeout, _}} ->
        :ok = Logger.error("Timeout!")

        {:error, :etimedout}

      other ->
        :ok = Logger.error("Unexpected result: #{inspect(other)}")

        {:error, :unknown_error}
    end
  end

  defp discover_engine_id(uri, target_name) do
    timeout =
      Application.get_env(
        :snmp_ex,
        :engine_discovery_timeout
      )

    with {:error, _} <-
           :snmpm_config.get_agent_engine_id(target_name)
    do
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

  defp normalize_to_oids([[]]),
    do: []

  defp normalize_to_oids(objects) do
    objects
    |> Enum.reduce([], fn object, acc ->
      cond do
        :snmp_misc.is_oid(object) ->
          [object|acc]

        is_dotted_decimal(object) ->
          [string_oid_to_list(object)|acc]

        is_atom(object) ->
          {:ok, oid} = resolve_object_name_to_oid(object)

          [oid|acc]

        true ->
          atom = String.to_atom(object)
          {:ok, oid} = resolve_object_name_to_oid(atom)

          [oid|acc]
      end
    end)
    |> Enum.reverse()
  end

  defp _perform_snmp_op(
    op,
    varbinds,
    target,
    context,
    timeout
  ) do
    case op do
      :get ->
        oids =
          varbinds
          |> Enum.map(& &1.oid)
          |> normalize_to_oids

        :snmpm.sync_get(
          __MODULE__,
          target,
          context,
          oids,
          timeout
        )

      :get_next ->
        oids =
          varbinds
          |> Enum.map(& &1.oid)
          |> normalize_to_oids

        :snmpm.sync_get_next(
          __MODULE__,
          target,
          context,
          oids,
          timeout
        )

      :set ->
        vars_and_vals =
          varbinds
          |> Enum.map(fn v ->
            if Map.has_key?(v, :type) do
              {v.oid, v.type, v.value}
            else
              {v.oid, v.value}
            end
          end)

        :snmpm.sync_set(
          __MODULE__,
          target,
          context,
          vars_and_vals,
          timeout
        )
    end
  end

  defp perform_snmp_op(
    op,
    varbinds,
    uri,
    credential,
    options
  ) do
    target      = generate_target_name(uri, credential)
    erl_context =
      options
      |> Keyword.get(:context, "")
      |> :binary.bin_to_list()

    discover_fun = fn ->
      case discover_engine_id(uri, target) do
        {:ok,  eid} -> :binary.list_to_bin(eid)
        {:error, _} -> Utility.local_engine_id()
      end
    end

    engine_id =
      options
      |> Keyword.get_lazy(:engine_id, discover_fun)
      |> :binary.bin_to_list()

    with :ok <-
           register_usm_user(credential, engine_id),
         :ok <-
           register_agent(
             target,
             uri,
             credential,
             engine_id
           ),
         :ok <-
           warmup_engine_boots_and_engine_time(
             engine_id,
             target
           )
    do
      result =
        _perform_snmp_op(
          op,
          varbinds,
          target,
          erl_context,
          get_timeout()
        )

      groom_snmp_result(result)
    end
  end

  defp generate_target_name(uri, credential) do
    # Make a concise target name that is unique per host,
    # per credential

    "#{uri}#{inspect(credential)}"
    |> sha_sum
    |> :binary.bin_to_list()
  end

  @type object_name :: binary

  @type object_id
    :: object_name
     | [non_neg_integer, ...]

  @type asn1_type  :: atom | binary
  @type asn1_value :: any
  @type credential :: map

  @type req_varbind
    :: %{oid: object_id}
     | %{oid: object_id, type: asn1_type}
     | %{oid: object_id, type: asn1_type, value: asn1_value}

  @type varbind
    :: %{oid:   object_id,
         type:  asn1_type,
         value: asn1_value,
       }

  @type req_params
    :: %{uri: URI.t,
         credential: credential,
         varbinds: [req_varbind, ...],
       }

  @type req_options :: Keyword.t

  @type request_result
    :: {:ok, [varbind, ...]}
     | {:error, any}

  @spec request(req_params, req_options)
    :: request_result
  def request(
    %{uri: %{scheme: _, host: _, port: _} = uri,
      credential: credential,
      varbinds: varbinds,
    },
    options \\ []
  )   when is_list(varbinds)
       and is_list(options)
  do
    with op when not is_nil(op) <-
           ( cond do
               Enum.all?(
                 varbinds,
                 & &1[:oid] && &1[:value]
               ) ->
                 :set

               Enum.all?(
                 varbinds,
                 & &1[:oid] && (&1[:type] == :next)
               ) ->
                 :get_next

               Enum.all?(varbinds, & &1[:oid]) ->
                 :get

               true ->
                 :ok = Logger.error("Request contains unacceptable varbinds: #{inspect(varbinds)}")

                 {:error, :einval}
             end
           ),
         {:ok, ip_uri} <- resolve_host_in_uri(uri)
    do
      perform_snmp_op(
        op,
        varbinds,
        ip_uri,
        credential,
        options
      )
    end
  end

  #@spec walk(req_params, req_options)
  def walk(
    %{uri: uri,
      credential: credential,
      varbinds: [%{oid: object}|_],
    },
    options \\ []
  ) do
    [base_oid] = normalize_to_oids([object])

    %{oid: base_oid ++ [0]}
    |> Stream.iterate(fn %{oid: last_oid} ->
      %{uri: uri,
        credential: credential,
        varbinds: [%{oid: last_oid, type: :next}]
      }
      |> request(options)
      |> elem(1)
      |> List.first
    end)
    |> Stream.take_while(fn %{oid: oid} ->
      List.starts_with?(oid, base_oid)
    end)
    |> Stream.drop(1)
  end

  @type mib_name :: String.t()

  @spec load_mib(mib_name)
    :: :ok
     | {:error, term}
  def load_mib(mib_name) do
    erl_mib_name = :binary.bin_to_list(mib_name)

    case :snmpm.load_mib(erl_mib_name) do
      :ok ->
        :ok

      {:error, reason} = error ->
        :ok = Logger.error("Unable to load MIB #{inspect(mib_name)}: #{reason}")

        error
    end
  end

  @spec load_mib!(mib_name)
    :: :ok
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
      when is_atom(name)
  do
    try do
      with {:ok, [oid]} <- :snmpm.name_to_oid(name),
        do: {:ok, oid}
    rescue
      e in ArgumentError ->
        :ok = Logger.warn("Unhandled exception: did you forget to `SNMP.start`?")

        reraise(e, System.stacktrace())
    end
  end

  @doc """
  Returns a keyword list containing the given SNMP
  credentials.

  ## Example

      iex> SNMP.credential(%{community: "public"})
      %SNMP.CommunityCredential{community: 'public'}

      iex> SNMP.credential(
      ...>   %{version: :v2, community: "public"}
      ...> )
      %SNMP.CommunityCredential{
        version: :v2,
        sec_model: :v2c,
        community: 'public',
      }

      iex> SNMP.credential(%{sec_name: "user"})
      %SNMP.USMCredential{sec_name: 'user'}

      iex> SNMP.credential(
      ...>   %{sec_name: "user",
      ...>     auth: :sha,
      ...>     auth_pass: "authpass",
      ...>   }
      ...> )
      %SNMP.USMCredential{
        sec_name: 'user',
        sec_level: :authNoPriv,
        auth: :usmHMACSHAAuthProtocol,
        auth_pass: 'authpass',
      }

      iex> SNMP.credential(
      ...>   %{sec_name: "user",
      ...>     auth: :sha,
      ...>     auth_pass: "authpass",
      ...>     priv: :aes,
      ...>     priv_pass: "privpass",
      ...>   }
      ...> )
      %SNMP.USMCredential{
        sec_name: 'user',
        sec_level: :authPriv,
        auth: :usmHMACSHAAuthProtocol,
        auth_pass: 'authpass',
        priv: :usmAesCfb128Protocol,
        priv_pass: 'privpass',
      }
  """
  def credential(
    %{version: :v2,
      community: community,
    }
  )   when is_binary(community)
  do
    %CommunityCredential{
      version: :v2,
      sec_model: :v2c,
      community: :binary.bin_to_list(community),
    }
  end

  def credential(%{community: community})
      when is_binary(community)
  do
    %CommunityCredential{
      version: :v1,
      sec_model: :v1,
      community: :binary.bin_to_list(community),
    }
  end

  def credential(
    %{sec_name: sec_name,
      auth: auth,
      auth_pass: auth_pass,
      priv: priv,
      priv_pass: priv_pass,
    }
  )   when is_binary(sec_name)
       and auth in [:md5, :sha]
       and is_binary(auth_pass)
       and priv in [:des, :aes]
       and is_binary(priv_pass)
  do
    %USMCredential{
      sec_level: :authPriv,
      sec_name: :binary.bin_to_list(sec_name),
      auth: auth_proto_to_snmpm_auth(auth),
      auth_pass: :binary.bin_to_list(auth_pass),
      priv: priv_proto_to_snmpm_priv(priv),
      priv_pass: :binary.bin_to_list(priv_pass),
    }
  end

  def credential(
    %{sec_name: sec_name,
      auth: auth,
      auth_pass: auth_pass,
    }
  )   when is_binary(sec_name)
       and auth in [:md5, :sha]
       and is_binary(auth_pass)
  do
    %USMCredential{
      sec_level: :authNoPriv,
      sec_name: :binary.bin_to_list(sec_name),
      auth: auth_proto_to_snmpm_auth(auth),
      auth_pass: :binary.bin_to_list(auth_pass),
    }
  end

  def credential(%{sec_name: sec_name})
      when is_binary(sec_name)
  do
    %USMCredential{
      sec_name: :binary.bin_to_list(sec_name),
    }
  end

  defp auth_proto_to_snmpm_auth(:md5), do: :usmHMACMD5AuthProtocol
  defp auth_proto_to_snmpm_auth(:sha), do: :usmHMACSHAAuthProtocol

  defp priv_proto_to_snmpm_priv(:des), do: :usmDESPrivProtocol
  defp priv_proto_to_snmpm_priv(:aes), do: :usmAesCfb128Protocol

  @doc """
  Converts `oid` to dot-delimited string.

  ## Example

      iex> SNMP.list_oid_to_string([1,3,6,1,2,1,1,5,0])
      "1.3.6.1.2.1.1.5.0"

  """
  @spec list_oid_to_string([non_neg_integer])
    :: String.t()
     | no_return
  def list_oid_to_string(oid) when is_list(oid),
    do: Enum.join(oid, ".")

  @doc """
  Converts dot-delimited `oid` string to list.

  ## Example

      iex> SNMP.string_oid_to_list("1.3.6.1.2.1.1.5.0")
      [1,3,6,1,2,1,1,5,0]

  """
  @spec string_oid_to_list(String.t())
    :: [non_neg_integer]
     | no_return
  def string_oid_to_list(oid) when is_binary(oid) do
    oid
    |> String.split(".", trim: true)
    |> Enum.map(&String.to_integer/1)
  end
end
