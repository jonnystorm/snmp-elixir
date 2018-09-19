defmodule SNMP.Test do
  use ExUnit.Case, async: false
  doctest SNMP

  # For a full explanation of magic values, please see
  # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html

  @moduletag :integrated

  @sysname_oid [1, 3, 6, 1, 2, 1, 1, 5, 0]
  @sysname_value {
    @sysname_oid,
    :"OCTET STRING",
    'new system name'
  }

  # Presumably working agent, but has frequent troubles
  @working_agent "demo.snmplabs.com"

  # Optimistically, should a broken agent
  @borking_agent "localhost:65535"

  setup_all do
    {:ok, _pid} = SNMP.start_link()
    :ok
  end

  defp get_credential(:none, :none) do
    SNMP.credential([
      :v3,
      :no_auth_no_priv,
      "usr-none-none"
    ])
  end

  defp get_credential(auth, :none)
       when auth in [:md5, :sha] do
    SNMP.credential([
      :v3,
      :auth_no_priv,
      "usr-#{Atom.to_string(auth)}-none",
      auth,
      "authkey1"
    ])
  end

  defp get_credential(auth, priv)
      when auth in [:md5, :sha]
       and priv in [:des, :aes]
  do
    SNMP.credential([
      :v3,
      :auth_priv,
      "usr-#{Atom.to_string(auth)}-#{Atom.to_string(priv)}",
      auth,
      "authkey1",
      priv,
      "privkey1"
    ])
  end

  defp get_sysname_with_engine_id(credential, agent) do
    get_sysname(
      credential,
      agent,
      engine_id: <<0x80004FB805636C6F75644DAB22CC::14*8>>
    )
  end

  defp get_sysname(credential, agent, opts \\ []) do
    SNMP.get(@sysname_oid, agent, credential, opts)
  end

  test "Hostname resolution breaks gracefully" do
    hostname = "x80004fb805636c6f75644dab22cc.local"

    result =
      :none
      |> get_credential(:none)
      |> get_sysname_with_engine_id(hostname)

    assert result == {:error, :nxdomain}
  end

  describe "v3 GET noAuthNoPriv" do
    test "get without engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname_with_engine_id(@working_agent)

      assert result == [@sysname_value]
    end

    test "timeout without engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname_with_engine_id(@borking_agent)

      assert result == {:error, :etimedout}
    end

    test "get with engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname(@working_agent)

      assert result == [@sysname_value]
    end

    test "timeout with engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname(@borking_agent)

      assert result == {:error, :etimedout}
    end
  end

  describe "v3 get authNoPriv" do
    test "get without engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname_with_engine_id(@working_agent)

        assert result == [@sysname_value]
      end
    end

    test "timeout without engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname_with_engine_id(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end

    test "get with engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname(@working_agent)

        assert result == [@sysname_value]
      end
    end

    test "timeout with engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end
  end

  describe "v3 get authPriv" do
    test "get without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname_with_engine_id(@working_agent)

        assert result == [@sysname_value]
      end
    end

    test "timeout without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname_with_engine_id(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end

    test "get with engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname(@working_agent)

        assert result == [@sysname_value]
      end
    end

    test "timeout with engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes]
      do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname(@borking_agent)

        assert result == {:error, :etimedout}
      end
    end
  end
end
