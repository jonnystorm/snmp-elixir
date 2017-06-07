defmodule SNMP.DiscoverAgent.Test do
  use ExUnit.Case, async: false

  alias SNMP.DiscoverAgent

  defp start_agent(opts \\ []) do
    {:ok, _pid} = DiscoverAgent.start_link([], opts)
  end

  defp setup_start_agent(context) do
    start_agent()
    context
  end

  describe "find engine id" do
    setup [:setup_start_agent]

    test "agent engine id" do
      assert DiscoverAgent.find_engine_id({127, 0, 0, 1}, port: 6000) == 'snmp_discovery_agent_engine'
    end
  end

end
