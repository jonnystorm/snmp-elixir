defmodule SNMP.Test do
  use ExUnit.Case, async: false
  doctest SNMP

  # For a full explanation of magic values, please see
  # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html

  @syswalk_oid [1, 3, 6, 1, 2, 1, 1]
  @sysdesc_oid [1, 3, 6, 1, 2, 1, 1, 2, 0]
  @sysname_oid [1, 3, 6, 1, 2, 1, 1, 5, 0]

  @sysdesc_value {
    @sysdesc_oid,
    :"OBJECT IDENTIFIER",
    [1, 3, 6, 1, 4, 1, 8072, 3, 2, 10]
  }
  @sysname_value {
    @sysname_oid,
    :"OCTET STRING",
    'zeus.snmplabs.com (you can change this!)'
  }

  # Working docker agents
  @agent URI.parse("snmp://localhost:1161")
  @agent_v3_md5_none URI.parse("snmp://localhost:1162")
  @agent_v3_sha_none URI.parse("snmp://localhost:1163")
  @agent_v3_md5_des URI.parse("snmp://localhost:1164")
  @agent_v3_md5_aes URI.parse("snmp://localhost:1165")
  @agent_v3_sha_aes URI.parse("snmp://localhost:1166")
  @agent_v3_sha_aes URI.parse("snmp://localhost:1167")

  # Optimistically, should be a broken agent
  @broken_agent "localhost:65535"

  defp get_credential(:none, :none) do
    SNMP.Credential.login([
      :v3,
      :no_auth_no_priv,
      "testing"
    ])
  end

  defp get_credential(auth, :none)
       when auth in [:md5, :sha] do
    SNMP.Credential.login([
      :v3,
      :auth_no_priv,
      "testing",
      auth,
      "authkey1"
    ])
  end

  defp get_credential(auth, priv)
       when auth in [:md5, :sha] and
              priv in [:des, :aes] do
    SNMP.Credential.login([
      :v3,
      :auth_priv,
      "testing",
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
      engine_id: <<0x80004FB805636C6F75644DAB22CC::14*8>>,
      context: "fe01ce2a7fbac8fafaed7c982a04e229",
      community: "demo"
    )
  end

  defp get_sysname(
         credential,
         agent,
         opts \\ [
           context: "fe01ce2a7fbac8fafaed7c982a04e229",
           community: "demo"
         ]
       ) do
    SNMP.get(@sysname_oid, agent, credential, opts)
  end

  describe "normalize to oid" do
    test "string to oid" do
      assert [[1, 2, 3, 4]] ==
               SNMP.normalize_to_oid("1.2.3.4")
    end

    test "oid stays oid" do
      assert [[1, 2, 3, 4]] ==
               SNMP.normalize_to_oid([1, 2, 3, 4])
    end
  end

  describe "v1" do
    @cred SNMP.Credential.login(:v1, "public")

    test "get" do
      result = SNMP.get(@sysdesc_oid, @agent, @cred)
      assert result == [@sysdesc_value]
    end

    test "set" do
      result =
        SNMP.set(
          @sysname_oid,
          @agent,
          @cred,
          "test",
          "string"
        )

      assert result == [
               {@sysname_oid, :"OCTET STRING", 'test'}
             ]
    end

    test "walk" do
      result = SNMP.walk(@syswalk_oid, @agent, @cred)
      assert Enum.count(result) == 32
    end
  end

  describe "v2" do
    @cred SNMP.Credential.login(:v2c, "public")
    test "get" do
      result = SNMP.get(@sysdesc_oid, @agent, @cred)

      assert result == [@sysdesc_value]
    end

    test "set" do
      result =
        SNMP.set(
          @sysname_oid,
          @agent,
          @cred,
          "test_v2",
          "string"
        )

      assert result == [
               {@sysname_oid, :"OCTET STRING", 'test_v2'}
             ]
    end

    test "walk" do
      result = SNMP.walk(@syswalk_oid, @agent, @cred)
      assert Enum.count(result) == 32
    end
  end

  describe "v3 get authNoPriv" do
    @tag :skip
    test "md5 get without engine discovery" do
      result =
        :md5
        |> get_credential(:none)
        |> get_sysname_with_engine_id(@agent_v3_md5_none)

      assert result == [@sysname_value]
    end

    @tag :skip
    test "sha get without engine discovery" do
      result =
        :sha
        |> get_credential(:none)
        |> get_sysname_with_engine_id(@agent_v3_sha_none)

      assert result == [@sysname_value]
    end

    @tag :skip
    test "get on not working SNMP timeouts without engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname_with_engine_id(@broken_agent)

        assert result == {:error, :etimedout}
      end
    end

    @tag :skip
    test "md5 get with engine discovery" do
      result =
        :md5
        |> get_credential(:none)
        |> get_sysname(@agent_v3_md5_none)

      assert result == [@sysname_value]
    end

    @tag :skip
    test "sha get with engine discovery" do
      result =
        :sha
        |> get_credential(:none)
        |> get_sysname(@agent_v3_sha_none)

      assert result == [@sysname_value]
    end

    @tag :skip
    test "timeout with engine discovery" do
      for auth <- [:md5, :sha] do
        result =
          auth
          |> get_credential(:none)
          |> get_sysname(@broken_agent)

        assert result == {:error, :etimedout}
      end
    end
  end

  describe "v3 get authPriv" do
    @tag :skip
    test "get without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes] do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname_with_engine_id(@agent)

        assert result == [@sysname_value]
      end
    end

    @tag :skip
    test "timeout without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes] do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname_with_engine_id(@broken_agent)

        assert result == {:error, :etimedout}
      end
    end

    @tag :skip
    test "get with engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes] do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname(@agent)

        assert result == [@sysname_value]
      end
    end

    @tag :skip
    test "timeout with engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes] do
        result =
          auth
          |> get_credential(priv)
          |> get_sysname(@broken_agent)

        assert result == {:error, :etimedout}
      end
    end
  end
end
