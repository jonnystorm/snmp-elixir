defmodule SNMP.Supervisor do
  use Supervisor

  def start_link(_) do
    Supervisor.start_link(__MODULE__, [], name: __MODULE__)
  end

  def init(_) do
    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    children = [
      SNMP,
      SNMP.DiscoveryAgent,
    ]

    opts = [strategy: :one_for_one]

    Supervisor.init(children, opts)
  end
end
