defmodule SNMP.Test do
  use ExUnit.Case, async: false
  doctest SNMP, except: [request: 2, walk: 2]

  # For a full explanation of magic values, please see
  # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html

  @moduletag :integrated

  @sysname_oid [1, 3, 6, 1, 2, 1, 1, 5, 0]
  @sysname_result %{
    oid: @sysname_oid,
    type: :"OCTET STRING",
    value: "test-52567"
  }

  # Presumably working agent, but has frequent troubles
  @working_agent "demo.snmplabs.com:1161"

  # Optimistically, should be a broken agent
  @borking_agent "localhost:65535"

  defp get_credential(:none, :none),
    do: SNMP.credential(%{sec_name: "usr-none-none"})

  defp get_credential(auth, :none)
      when auth in [:md5, :sha]
  do
    %{sec_name: "usr-#{auth}-none",
      auth: auth,
      auth_pass: "authkey1",
    }
    |> SNMP.credential
  end

  defp get_credential(auth, priv)
      when auth in [:md5, :sha]
       and priv in [:des, :aes]
  do
    %{sec_name: "usr-#{auth}-#{priv}",
      auth: auth,
      auth_pass: "authkey1",
      priv: priv,
      priv_pass: "privkey1"
    }
    |> SNMP.credential
  end

  defp get_sysname_with_engine_id(credential, agent) do
    get_sysname(
      credential,
      agent,
      engine_id: <<0x80004fb805636c6f75644dab22cd::14*8>>
    )
  end

  defp get_sysname(credential, agent, opts \\ []) do
    %{uri: URI.parse("snmp://#{agent}"),
      credential: credential,
      varbinds: [%{oid: @sysname_oid}],
    }
    |> SNMP.request(opts)
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

      assert result == {:ok, [@sysname_result]}
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

      assert result == {:ok, [@sysname_result]}
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

        assert result == {:ok, [@sysname_result]}
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

        assert result == {:ok, [@sysname_result]}
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

        assert result == {:ok, [@sysname_result]}
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

        assert result == {:ok, [@sysname_result]}
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

  describe "v1" do
    test "set" do
      req =
        %{uri: URI.parse("snmp://#{@working_agent}"),
          credential: SNMP.credential(%{community: "public"}),
          varbinds: [%{oid: @sysname_oid}],
        }

      {:ok, [%{value: v}]} = before = SNMP.request(req)

      {_, _, us} = :erlang.now

      new_v = "test-#{us}"

      %{req |
        varbinds: [
          %{oid: @sysname_oid, type: :s, value: new_v}
        ],
      }
      |> SNMP.request

      refute before == SNMP.request(req)

      %{req |
        varbinds: [
          %{oid: @sysname_oid, type: :s, value: v}
        ],
      }
      |> SNMP.request
    end
  end

  describe "v2" do
    test "set" do
      req =
        %{uri: URI.parse("snmp://#{@working_agent}"),
          credential: SNMP.credential(
            %{version: :v2, community: "public"}
          ),
          varbinds: [%{oid: @sysname_oid}],
        }

      {:ok, [%{value: v}]} = before = SNMP.request(req)

      {_, _, us} = :erlang.now

      new_v = "test-#{us}"

      %{req |
        varbinds: [%{oid: @sysname_oid, value: new_v}],
      }
      |> SNMP.request

      refute before == SNMP.request(req)

      %{req |
        varbinds: [
          %{oid: @sysname_oid, type: :s, value: v}
        ],
      }
      |> SNMP.request
    end
  end
end
