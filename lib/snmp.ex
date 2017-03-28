# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SNMP do
  @moduledoc """
  An SNMP client library for Elixir
  """
  use GenServer

  require Logger

  def start do
    :snmpm.start()
    :snmpm.register_user(__MODULE__, :snmpm_user_default, self())

    GenServer.start(__MODULE__, [])
  end

  defp get_timeout,
    do: Application.get_env(:snmp_ex, :timeout)

  defp get_max_repetitions,
    do: Application.get_env(:snmp_ex, :max_repetitions)

  defp gethostbyname(host) do
    result =
      host
        |> :binary.bin_to_list
        |> :inet.gethostbyname

    with {:ok, {_, _, _, _, family, [addr|_]}} <- result do
        list = Tuple.to_list addr

        delimiter = %{4 => ".", 6 => ":"}[family]

        list
          |> Enum.join(delimiter)
          |> NetAddr.ip
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
         {:error, _} <- parse_ip(gethostbyname host)
    do
      :ok = Logger.error("Unable to resolve host #{inspect host}")

      {:error, :einval}
    end
  end

  defp get_transport_from_netaddr(%NetAddr.IPv4{}),
    do: :transportDomainUdpIpv4
  defp get_transport_from_netaddr(%NetAddr.IPv6{}),
    do: :transportDomainUdpIpv6

  defp get_local_engine_id, do: <<0x8000000006::8*5>>

  defp register_usm_user(credential, engine_id) do
    usm_keys = [:sec_name, :auth, :auth_key, :priv, :priv_key]
    usm_config = Keyword.take(credential, usm_keys)

    :snmpm.register_usm_user(engine_id, usm_config[:sec_name], usm_config)
  end

  defp register_agent(target, uri, credential, engine_id) do
    with {:ok, netaddr} <- resolve_host_to_netaddr(uri.host) do
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
    engine_id = :binary.bin_to_list(get_local_engine_id())

    if credential[:sec_model] == :usm do
      register_usm_user(credential, engine_id)
    end

    case register_agent(target, uri, credential, engine_id) do
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
  """
  @spec credential(list) :: Keyword.t
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
  """
  @spec credential(:v1, String.t) :: Keyword.t
  @spec credential(:v2c, String.t) :: Keyword.t

  def credential(version, community)
  def credential(:v1, community) do
    [ version:   :v1,
      sec_model: :v1,
      community: :binary.bin_to_list(community),
    ]
  end
  def credential(:v2c, community) do
    [ version:   :v2,
      sec_model: :v2c,
      community: :binary.bin_to_list(community),
    ]
  end

  @doc """
  Returns a keyword list containing the given SNMPv3 noAuthNoPriv credentials.
  """
  @spec credential(:v3, :no_auth_no_priv, String.t) :: Keyword.t

  def credential(version, sec_level, sec_name)
  def credential(:v3, :no_auth_no_priv, sec_name) do
    [ version:   :v3,
      sec_model: :usm,
      sec_level: :noAuthNoPriv,
      sec_name:  :binary.bin_to_list(sec_name),
    ]
  end

  defp convert_password_to_intermediate_key(password, algorithm)
      when algorithm in [:md5, :sha]
  do
    intermediate_key =
      password
        |> :binary.bin_to_list
        |> Stream.cycle
        |> Enum.take(1048576)

    :crypto.hash(algorithm, intermediate_key)
  end

  defp localize_key(key, algorithm, engine_id)
      when algorithm in [:md5, :sha]
  do
    :crypto.hash(algorithm, "#{key}#{engine_id}#{key}")
  end

  def convert_password_to_key(password, algorithm, engine_id \\ nil)
  def convert_password_to_key(password, algorithm, engine_id) do
    # Per RFC 3414, except use of localEngineID
    eid = engine_id || get_local_engine_id()

    password
      |> convert_password_to_intermediate_key(algorithm)
      |> localize_key(algorithm, eid)
      |> :binary.bin_to_list
  end

  @doc """
  Returns a keyword list containing the given SNMPv3 authNoPriv credentials.
  """
  @spec credential(:v3, :auth_no_priv, String.t, :md5|:sha, String.t) :: Keyword.t

  def credential(version, sec_level, sec_name, auth_proto, auth_pass)
  def credential(:v3, :auth_no_priv, sec_name, auth_proto, auth_pass)
      when auth_proto in [:md5, :sha]
  do
    [ version:   :v3,
      sec_model: :usm,
      sec_level: :authNoPriv,
      sec_name:  :binary.bin_to_list(sec_name),
      auth:      auth_proto_to_snmpm_auth(auth_proto),
      auth_key:  convert_password_to_key(auth_pass, auth_proto),
    ]
  end

  defp auth_proto_to_snmpm_auth(:md5), do: :usmHMACMD5AuthProtocol
  defp auth_proto_to_snmpm_auth(:sha), do: :usmHMACSHAAuthProtocol

  defp priv_proto_to_snmpm_auth(:des), do: :usmDESPrivProtocol
  defp priv_proto_to_snmpm_auth(:aes), do: :usmAesCfb128Protocol

  @doc """
  Returns a keyword list containing the given SNMPv3 authPriv credentials.
  """
  @spec credential(:v3, :auth_priv, String.t, :md5|:sha, String.t, :des|:aes, String.t) :: Keyword.t

  def credential(version, sec_level, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)
  def credential(:v3, :auth_priv, sec_name, auth_proto, auth_pass, priv_proto, priv_pass)
      when auth_proto in [:md5, :sha]
       and priv_proto in [:des, :aes]
  do
    # http://erlang.org/doc/man/snmpm.html#register_usm_user-3
    auth_key = convert_password_to_key(auth_pass, auth_proto)
    priv_key =
      priv_pass
        |> convert_password_to_key(auth_proto)
        |> Enum.slice(0..15)

    [ version:   :v3,
      sec_model: :usm,
      sec_level: :authPriv,
      sec_name:  :binary.bin_to_list(sec_name),
      auth:      auth_proto_to_snmpm_auth(auth_proto),
      auth_key:  auth_key,
      priv:      priv_proto_to_snmpm_auth(priv_proto),
      priv_key:  priv_key,
    ]
  end

  @doc """
  Converts `oid` to dot-delimited string.
  """
  @spec list_oid_to_string([non_neg_integer]) :: String.t

  def list_oid_to_string(oid) when is_list oid do
    Enum.join(oid, ".")
  end

  @doc """
  Converts dot-delimited `oid` string to list.
  """
  @spec string_oid_to_list(String.t) :: [non_neg_integer]

  def string_oid_to_list(oid) when is_binary oid do
    oid
      |> String.split(".", [trim: true])
      |> Enum.map(&String.to_integer/1)
  end
end
