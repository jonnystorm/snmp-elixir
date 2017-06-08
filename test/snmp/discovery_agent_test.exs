defmodule SNMP.DiscoveryAgent.Test do
  use ExUnit.Case, async: false

  alias SNMP.DiscoveryAgent

  defp start_agent(opts \\ []) do
    {:ok, _pid} = DiscoveryAgent.start_link([], opts)
  end

  defp setup_start_agent(context) do
    start_agent()
    context
  end

  describe "find engine id" do
    setup [:setup_start_agent]

    test "agent engine id" do
      assert DiscoveryAgent.find_engine_id({127, 0, 0, 1}, port: 6000) == 'snmp_discovery_agent_engine'
    end
  end

end
