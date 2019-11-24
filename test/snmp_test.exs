defmodule SNMP.Test do
  use ExUnit.Case, async: false
  doctest SNMP

  # For a full explanation of magic values, please see
  # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html

  @moduletag :integrated

  @sysname_oid [1, 3, 6, 1, 2, 1, 1, 5, 0]
  @sysname_result %{
    oid: @sysname_oid,
    type: :"OCTET STRING",
    value: "new sys name"
  }

  # Presumably working agent, but has frequent troubles
  @working_agent "demo.snmplabs.com"

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
      engine_id: <<0x80004FB805636C6F75644DAB22CC::14*8>>
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

      assert result == [@sysname_result]
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

      assert result == [@sysname_result]
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

        assert result == [@sysname_result]
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

        assert result == [@sysname_result]
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

        assert result == [@sysname_result]
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

        assert result == [@sysname_result]
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
      uri  = URI.parse("snmp://#{@working_agent}")
      cred = SNMP.credential(%{community: "public"})

      before_set =
        %{uri: uri,
          credential: cred,
          varbinds: [%{oid: @sysname_oid}],
        }
        |> SNMP.request

      refute before_set ==
        [ { :ok,
            %{oid: @sysname_oid,
              type: :"OCTET STRING",
              value: 'test',
            }
          }
        ]

      set_result =
        %{uri: uri,
          credential: cred,
          varbinds: [%{oid: @sysname_oid, value: "test"}],
        }
        |> SNMP.request

      assert set_result ==
        [ { :ok,
            %{oid: @sysname_oid,
              type: :"OCTET STRING",
              value: 'test',
            }
          }
        ]

      after_set =
        %{uri: uri,
          credential: cred,
          varbinds: [%{oid: @sysname_oid}],
        }
        |> SNMP.request

      assert after_set ==
        [ { :ok,
            %{oid: @sysname_oid,
              type: :"OCTET STRING",
              value: 'test',
            }
          }
        ]
    end
  end

  describe "v2" do
    test "set" do
      uri  = URI.parse("snmp://#{@working_agent}")
      cred =
        %{version: :v2,
          community: "public",
        }
        |> SNMP.credential

      before_set =
        %{uri: uri,
          credential: cred,
          varbinds: [%{oid: @sysname_oid}],
        }
        |> SNMP.request

      refute before_set ==
        [ { :ok,
            %{oid: @sysname_oid,
              type: :"OCTET STRING",
              value: "test",
            }
          }
        ]

      set_result =
        %{uri: uri,
          credential: cred,
          varbinds: [%{oid: @sysname_oid, value: "test"}],
        }
        |> SNMP.request

      assert set_result ==
        [ { :ok,
            %{oid: @sysname_oid,
              type: :"OCTET STRING",
              value: 'test',
            }
          }
        ]

      after_set =
        %{uri: uri,
          credential: cred,
          varbinds: [%{oid: @sysname_oid}],
        }
        |> SNMP.request

      assert after_set ==
        [ { :ok,
            %{oid: @sysname_oid,
              type: :"OCTET STRING",
              value: "test",
            }
          }
        ]
    end
  end
end
