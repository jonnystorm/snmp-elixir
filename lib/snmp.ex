# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SNMP do
  @moduledoc """
  An SNMP client library for Elixir.
  """

  alias SNMP.{Credential, Utility}

  require Logger

  @crypto Application.get_env(:snmp_ex, :crypto_module)

  defmodule Credential do
    defstruct [
      :version,
      :sec_model,
      :community,
      :sec_level,
      :sec_name,
      :auth,
      :auth_key,
      :priv,
      :priv_key,
    ]

    @type t :: %__MODULE__{
        version: :v1 | :v2 | :v3,
      sec_model: :v1 | :v2c | :usm,
      community: nil | [byte],
      sec_level: nil | :noAuthNoPriv | :authNoPriv | :authPriv,
       sec_name: nil | [byte],
           auth: nil | :usmHMACMD5AuthProtocol | :usmHMACSHAAuthProtocol,
       auth_key: nil | [byte],
           priv: nil | :usmDESPrivProtocol | :usmAesCfb128Protocol,
       priv_key: nil | [byte],
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

  defp get_host_by_name(host) do
    result = :inet.gethostbyname :binary.bin_to_list(host)

    with {:ok, {_, _, _, _, family, [addr|_]}} <- result
    do
      delimiter = get_delimiter_by_family(family)

      addr
      |> Tuple.to_list
      |> Enum.join(delimiter)
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
         {:error, _} <- parse_ip(get_host_by_name host)
    do
      :ok = Logger.error("Unable to resolve host #{inspect host}")

      {:error, :einval}
    end
  end

  defp get_transport_from_netaddr(%NetAddr.IPv4{}),
    do: :transportDomainUdpIpv4
  defp get_transport_from_netaddr(%NetAddr.IPv6{}),
    do: :transportDomainUdpIpv6

  defp register_usm_user(credential, engine_id) do
    usm_config =
      credential
      |> Keyword.take([:sec_name, :auth, :auth_key, :priv, :priv_key])
      |> Enum.filter(fn {_, v} -> not is_nil(v) end)

    :snmpm.register_usm_user(engine_id, usm_config[:sec_name], usm_config)
  end

  defp register_agent(target, uri, credential, engine_id) do
    with {:ok, netaddr} <- resolve_host_to_netaddr(uri.host)
    do
      config = [ engine_id: engine_id,
                   address: NetAddr.netaddr_to_list(netaddr),
                      port: uri.port || 161,
                   tdomain: get_transport_from_netaddr(netaddr),
                   version: credential[:version],
                 sec_model: credential[:sec_model],
               ] ++ Keyword.take(credential, [:sec_level, :sec_name, :community])

      :ok = Logger.debug("Will register agent #{uri} with target #{inspect target} and config #{inspect config}.")

      :snmpm.register_agent(__MODULE__, target, config)
    end
  end

  def resolve_mib_name(name) do
    # TODO: Implement this
    name
  end

  defp normalize_to_oids(objects) do
    objects
    |> Enum.reduce([], fn(object, acc) ->
      cond do
        is_list object ->
          if Enum.all?(object, &is_integer/1) do
            [object|acc]
          else
            acc
          end

        object =~ ~r/^\.?\d(\.\d)+$/ ->
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

  defp groom_snmp_result(result) do
    case result do
      {:ok, {:noError, 0, varbinds}, _} ->
        # TODO: Find out what last value in tuple is
        Enum.map(varbinds, fn {_, oid, type, value, _?} ->
          {oid, type, value}
        end)

      {:error, {:send_failed, _, reason}} ->
        :ok = Logger.error("Send failed: #{inspect reason}")

        {:error, reason}

      {:error, {:invalid_sec_info, sec_info, _}} ->
        :ok = Logger.error("Invalid credential values: #{inspect sec_info}")

        {:error, :invalid_sec_info}

      {:error, {:timeout, _}} ->
        :ok = Logger.error("Timeout!")

        {:error, :etimedout}

      other ->
        :ok = Logger.error("Unexpected result: #{inspect other}")

        {:error, :unknown_error}
    end
  end

  defp _perform_snmp_op(op, oids, target, context, timeout) do
    case op do
      :get -> :snmpm.sync_get(__MODULE__, target, context, oids, timeout)

    end |> groom_snmp_result
  end

  defp perform_snmp_op(op, objects, agent, credential, context) do
    uri = normalize_to_uri(agent)
    oids = normalize_to_oids(objects)
    target = :binary.bin_to_list :crypto.hash(:sha, "#{uri}#{inspect credential}")
    timeout = get_timeout()
    # TODO: Using RFC 5343 localEngineID: is this acceptable?
    engine_id = :binary.bin_to_list(Utility.get_local_engine_id())
    cred_list = Map.to_list credential

    if cred_list[:sec_model] == :usm do
      register_usm_user(cred_list, engine_id)
    end

    case register_agent(target, uri, cred_list, engine_id) do
      :ok ->
        _perform_snmp_op(op, oids, target, context, timeout)

      {:error, {:already_registered, _}} ->
        _perform_snmp_op(op, oids, target, context, timeout)

      {:error, {:already_registered, _, _}} ->
        _perform_snmp_op(op, oids, target, context, timeout)

      {:error, reason} = error ->
        :ok = Logger.error("Unable to register agent for #{uri}: #{inspect reason}")

        error
    end
  end

  def get(objects, agent, credential, context \\ "")
  def get([h|_] = objects, agent, credential, context)
      when is_binary(h)
        or is_list(h)
  do
    perform_snmp_op(:get, objects, agent, credential, context)
  end

  def get(object, agent, credential, context),
    do: get([object], agent, credential, context)

  @doc """
  Returns a keyword list containing the given SNMPv1/2c/3 credentials.

  ## Example

      iex> SNMP.credential([:v1, "public"])
      %SNMP.Credential{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.credential([:v2c, "public"])
      %SNMP.Credential{version: :v2, sec_model: :v2c, community: 'public'}

      iex> SNMP.credential([:v3, :no_auth_no_priv, "user"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :noAuthNoPriv,
        sec_name:  'user'
      }

      iex> SNMP.credential([:v3, :auth_no_priv, "user", :md5, "authpass"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
      }

      iex> SNMP.credential([:v3, :auth_no_priv, "user", :sha, "authpass"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmDESPrivProtocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmDESPrivProtocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmAesCfb128Protocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential([:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"])
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmDESPrivProtocol,
        priv:      :usmAesCfb128Protocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }
  """
  @spec credential([atom | String.t]) :: Credential.t
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
      %SNMP.Credential{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.credential(:v2c, "public")
      %SNMP.Credential{version: :v2, sec_model: :v2c, community: 'public'}
  """
  @spec credential(:v1 | :v2c, String.t) :: Credential.t
  def credential(version, community)
  def credential(:v1, community) do
    %Credential{
      version:   :v1,
      sec_model: :v1,
      community: :binary.bin_to_list(community),
    }
  end
  def credential(:v2c, community) do
    %Credential{
      version:   :v2,
      sec_model: :v2c,
      community: :binary.bin_to_list(community),
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3 noAuthNoPriv credentials.

  ## Example

      iex> SNMP.credential(:v3, :no_auth_no_priv, "user")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :noAuthNoPriv,
        sec_name:  'user',
      }
  """
  @spec credential(:v3, :no_auth_no_priv, String.t) :: Credential.t
  def credential(version, sec_level, sec_name)
  def credential(:v3, :no_auth_no_priv, sec_name) do
    %Credential{
      version:   :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv,
      sec_name:  :binary.bin_to_list(sec_name),
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3 authNoPriv credentials.

  ## Example

      iex> SNMP.credential(:v3, :auth_no_priv, "user", :md5, "authpass")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
      }

      iex> SNMP.credential(:v3, :auth_no_priv, "user", :sha, "authpass")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
      }
  """
  @spec credential(:v3, :auth_no_priv, String.t, :md5|:sha, String.t) :: Credential.t
  def credential(version, sec_level, sec_name, auth_proto, auth_pass)
  def credential(:v3, :auth_no_priv, sec_name, auth_proto, auth_pass)
      when auth_proto in [:md5, :sha]
  do
    %Credential{
      version:   :v3,
      sec_model: :usm,
      sec_level: :authNoPriv,
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
  Returns `t:Credential.t/0` containing the given SNMPv3 authPriv credentials.

  ## Examples

      iex> SNMP.credential(:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmDESPrivProtocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmDESPrivProtocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACMD5AuthProtocol,
        auth_key:  [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141],
        priv:      :usmAesCfb128Protocol,
        priv_key:  [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92],
      }

      iex> SNMP.credential(:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass")
      %SNMP.Credential{
        version:   :v3,
        sec_model: :usm,
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :usmHMACSHAAuthProtocol,
        auth_key:  [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199],
        priv:      :usmAesCfb128Protocol,
        priv_key:  [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2],
      }
  """
  @spec credential(:v3, :auth_priv, String.t, :md5|:sha, String.t, :des|:aes, String.t) :: Credential.t
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

    %Credential{
      version:   :v3,
      sec_model: :usm,
      sec_level: :authPriv,
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
  @spec list_oid_to_string([non_neg_integer]) :: String.t
  def list_oid_to_string(oid) when is_list oid do
    Enum.join(oid, ".")
  end

  @doc """
  Converts dot-delimited `oid` string to list.

  ## Example

      iex> SNMP.string_oid_to_list("1.3.6.1.2.1.1.5.0")
      [1,3,6,1,2,1,1,5,0]
  """
  @spec string_oid_to_list(String.t) :: [non_neg_integer]
  def string_oid_to_list(oid) when is_binary oid do
    oid
    |> String.split(".", [trim: true])
    |> Enum.map(&String.to_integer/1)
  end
end
