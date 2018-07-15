defmodule SNMP.Test do
  use ExUnit.Case, async: false
  doctest SNMP

  # For a full explanation of magic values, please see
  # http://snmplabs.com/snmpsim/public-snmp-agent-simulator.html

  @moduletag :integrated

  @sysname_oid [1,3,6,1,2,1,1,5,0]
  @sysname_value {@sysname_oid, :"OCTET STRING", 'new system name'}

  setup_all do
    SNMP.start
  end

  defp get_credential(:none, :none) do
    SNMP.credential [
      :v3,
      :no_auth_no_priv,
      "usr-none-none",
    ]
  end

  defp get_credential(auth, :none)
      when auth in [:md5, :sha]
  do
    SNMP.credential [
      :v3,
      :auth_no_priv,
      "usr-#{Atom.to_string auth}-none",
      auth,
      "authkey1",
    ]
  end

  defp get_credential(auth, priv)
      when auth in [:md5, :sha]
       and priv in [:des, :aes]
  do
    SNMP.credential [
      :v3,
      :auth_priv,
      "usr-#{Atom.to_string auth}-#{Atom.to_string priv}",
      auth,
      "authkey1",
      priv,
      "privkey1",
    ]
  end

  defp get_sysname_with_engine_id(credential) do
    get_sysname(
      credential,
      [engine_id: <<0x80004fb805636c6f75644dab22cc::14*8>>]
    )
  end

  defp get_sysname(credential, opts \\ []) do
    snmp_agent = "demo.snmplabs.com"

    SNMP.get(@sysname_oid, snmp_agent, credential, opts)
  end

  describe "v3 GET noAuthNoPriv" do

    test "get without engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname_with_engine_id

      assert result == [@sysname_value]
    end

    test "get with engine discovery" do
      result =
        :none
        |> get_credential(:none)
        |> get_sysname

      assert result == [@sysname_value]
    end
  end

  describe "v3 get authNoPriv" do

    test "get without engine discovery" do
      for auth <- [:md5, :sha]
      do
        credential = get_credential(auth, :none)

        assert get_sysname_with_engine_id(credential) ==
          [@sysname_value]
      end
    end

    test "get with engine discovery" do
      for auth <- [:md5, :sha]
      do
        credential = get_credential(auth, :none)

        assert get_sysname(credential) == [@sysname_value]
      end
    end
  end

  describe "v3 get authPriv" do

    test "get without engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes]
      do
        credential = get_credential(auth, priv)

        assert get_sysname_with_engine_id(credential) ==
          [@sysname_value]
      end
    end

    test "get engine discovery" do
      for auth <- [:md5, :sha],
          priv <- [:des, :aes]
      do
        credential = get_credential(auth, priv)

        assert get_sysname(credential) == [@sysname_value]
      end
    end
  end
end
