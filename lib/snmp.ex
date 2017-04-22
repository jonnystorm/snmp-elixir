# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SNMP do
  @moduledoc """
  An SNMP client library for Elixir.
  """

  alias SNMP.{
    Utility,
    CommunityCredential,
    USMNoAuthNoPrivCredential,
    USMAuthNoPrivCredential,
    USMAuthPrivCredential,
  }

  require Logger

  @crypto Application.get_env(:snmp_ex, :crypto_module)

  @type snmp_credential :: CommunityCredential.t
                         | USMNoAuthNoPrivCredential.t
                         | USMAuthNoPrivCredential.t
                         | USMAuthPrivCredential.t

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

  defmodule USMNoAuthNoPrivCredential do
    defstruct [
        version: :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv,
       sec_name: nil,
    ]

    @type t :: %__MODULE__{
        version: :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv,
       sec_name: [byte],
    }
  end

  defmodule USMAuthNoPrivCredential do
    defstruct [
        version: :v3,
      sec_model: :usm,
      sec_level: :authNoPriv,
       sec_name: nil,
           auth: nil,
       auth_key: nil,
    ]

    @type t :: %__MODULE__{
        version: :v3,
      sec_model: :usm,
      sec_level: :authNoPriv,
       sec_name: [byte],
           auth: :usmHMACMD5AuthProtocol
               | :usmHMACSHAAuthProtocol,
       auth_key: [byte],
    }
  end

  defmodule USMAuthPrivCredential do
    defstruct [
        version: :v3,
      sec_model: :usm,
      sec_level: :authPriv,
       sec_name: nil,
           auth: nil,
       auth_key: nil,
           priv: nil,
       priv_key: nil,
    ]

    @type t :: %__MODULE__{
        version: :v3,
      sec_model: :usm,
      sec_level: :authPriv,
       sec_name: [byte],
           auth: :usmHMACMD5AuthProtocol
               | :usmHMACSHAAuthProtocol,
       auth_key: [byte],
           priv: :usmDESPrivProtocol
               | :usmAesCfb128Protocol,
       priv_key: [byte],
    }
  end

  def start do
    :ok = :snmpm.start()
    :ok = :snmpm.register_user(__MODULE__, :snmpm_user_default, self())

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

  defp register_usm_user(%{sec_model: :usm} = credential, engine_id) do
    username = credential.sec_name
    usm_keys = [:sec_name, :auth, :auth_key, :priv, :priv_key]
    config =
      credential
      |> Map.to_list
      |> Keyword.take(usm_keys)

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

  defp register_agent(target, uri, credential, engine_id) do
    with {:ok, netaddr} <- resolve_host_to_netaddr(uri.host)
    do
      cred_list = Map.to_list(credential)
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

  defp discover_engine_id(_uri) do
    # TODO: Figure out how to not fake this.
    Utility.local_engine_id
  end

  defp sha_sum(string) when is_binary(string),
    do: :crypto.hash(:sha, string)

  def resolve_mib_name(name) do
    # TODO: Implement this
    name
  end

  defp is_dotted_decimal(string),
    do: string =~ ~r/^\.?\d(\.\d)+$/

  defp normalize_to_oids(objects) do
    objects
    |> Enum.reduce([], fn(object, acc) ->
      cond do
        :snmp_misc.is_oid(object) ->
          [object|acc]

        is_dotted_decimal(object) ->
          [string_oid_to_list(object)|acc]

        true ->
          dot_dec = resolve_mib_name(object)

          [string_oid_to_list(dot_dec)|acc]
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
    oids = normalize_to_oids(objects)

    # Make a concise target name that is unique per host, per credential
    target      = :binary.bin_to_list sha_sum("#{uri}#{inspect credential}")
    erl_context = :binary.bin_to_list Keyword.get(options, :context, "")
    engine_id   =
      options
      |> Keyword.get(:engine_id, discover_engine_id(uri))
      |> :binary.bin_to_list

    with :ok <- register_usm_user(credential, engine_id),
         :ok <- register_agent(target, uri, credential, engine_id)
    do
      op
      |> _perform_snmp_op(oids, target, erl_context, get_timeout())
      |> groom_snmp_result
    end
  end

  def get(objects, agent, credential, options \\ [])

  def get([h|_] = objects, agent, credential, options)
      when is_list(h)
        or is_binary(h),
    do: perform_snmp_op(:get, objects, agent, credential, options)

  def get(object, agent, credential, options),
    do: get([object], agent, credential, options)

  @doc """
  Returns a keyword list containing the given SNMPv1/2c/3 credentials.

  ## Example

      iex> SNMP.credential([:v1, "public"])
      %SNMP.CommunityCredential{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.credential([:v2c, "public"])
      %SNMP.CommunityCredential{version: :v2, sec_model: :v2c, community: 'public'}

      iex> SNMP.credential([:v3, :no_auth_no_priv, "user"])
      %SNMP.USMNoAuthNoPrivCredential{sec_name:  'user'}

      iex> SNMP.credential([:v3, :auth_no_priv, "user", :md5, "authpass"])
      %SNMP.USMAuthNoPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
      }

      iex> SNMP.credential([:v3, :auth_no_priv, "user", :sha, "authpass"])
      %SNMP.USMAuthNoPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass"])
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmDESPrivProtocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass"])
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmDESPrivProtocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass"])
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmAesCfb128Protocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"])
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmDESPrivProtocol,
        priv:      :usmAesCfb128Protocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }

  """
  @spec credential([atom | String.t]) :: snmp_credential | no_return
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
  @spec credential(:v1 | :v2c, String.t) :: snmp_credential | no_return
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
      %SNMP.USMNoAuthNoPrivCredential{sec_name:  'user'}

  """
  @spec credential(:v3, :no_auth_no_priv, String.t) :: snmp_credential | no_return
  def credential(version, sec_level, sec_name)

  def credential(:v3, :no_auth_no_priv, sec_name),
    do: %USMNoAuthNoPrivCredential{sec_name: :binary.bin_to_list(sec_name)}

  @doc """
  Returns a keyword list containing the given SNMPv3 authNoPriv credentials.

  ## Example

      iex> SNMP.credential(:v3, :auth_no_priv, "user", :md5, "authpass")
      %SNMP.USMAuthNoPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
      }

      iex> SNMP.credential(:v3, :auth_no_priv, "user", :sha, "authpass")
      %SNMP.USMAuthNoPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
      }

  """
  @spec credential(:v3, :auth_no_priv, String.t, :md5|:sha, String.t) :: snmp_credential | no_return
  def credential(version, sec_level, sec_name, auth_proto, auth_pass)

  def credential(:v3, :auth_no_priv, sec_name, auth_proto, auth_pass)
      when auth_proto in [:md5, :sha]
  do
    %USMAuthNoPrivCredential{
      sec_name:  :binary.bin_to_list(sec_name),
      auth:      auth_proto_to_snmpm_auth(auth_proto),
      auth_key:  @crypto.convert_password_to_key(auth_pass, auth_proto),
    }
  end

  defp auth_proto_to_snmpm_auth(:md5), do: :usmHMACMD5AuthProtocol
  defp auth_proto_to_snmpm_auth(:sha), do: :usmHMACSHAAuthProtocol

  defp priv_proto_to_snmpm_auth(:des), do: :usmDESPrivProtocol
  defp priv_proto_to_snmpm_auth(:aes), do: :usmAesCfb128Protocol

  @doc """
  Returns `t:snmp_credential/0` containing the given SNMPv3 authPriv credentials.

  ## Examples

      iex> SNMP.credential(:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass")
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmDESPrivProtocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass")
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmDESPrivProtocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass")
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmAesCfb128Protocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass")
      %SNMP.USMAuthPrivCredential{
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmAesCfb128Protocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }

  """
  @spec credential(:v3, :auth_priv, String.t, :md5|:sha, String.t, :des|:aes, String.t) :: snmp_credential | no_return
  def credential(version, sec_level, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)

  def credential(:v3, :auth_priv, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)
      when auth_proto in [:md5, :sha]
       and priv_proto in [:des, :aes]
  do
    # http://erlang.org/doc/man/snmpm.html#register_usm_user-3
    auth_key = @crypto.convert_password_to_key(auth_pass, auth_proto)
    priv_key =
      priv_pass
      |> @crypto.convert_password_to_key(auth_proto)
      |> Enum.slice(0..15)

    %USMAuthPrivCredential{
      sec_name:  :binary.bin_to_list(sec_name),
      auth:      auth_proto_to_snmpm_auth(auth_proto),
      auth_key:  auth_key,
      priv:      priv_proto_to_snmpm_auth(priv_proto),
      priv_key:  priv_key,
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
