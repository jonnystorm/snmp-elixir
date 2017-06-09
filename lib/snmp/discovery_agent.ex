defmodule SNMP.DiscoveryAgent do

  @moduledoc """
  Provides abstractions to SNMP engine discovery through snmp agent
  """

  use GenServer
  require Logger

  def start_link(state \\ [], opts \\ []) do
    GenServer.start_link(__MODULE__, state, [name: __MODULE__] ++ opts)
  end

  def init(opts) do
    _ = GenServer.cast(self(), {:seed_and_start_agent, opts})

    {:ok, []}
  end

  defp mandatory_config_files do
    [ "snmp/agent/agent.conf",
      "snmp/agent/standard.conf",
      "snmp/agent/usm.conf",
      "snmp/agent/community.conf",
    ]
  end

  def handle_cast({:seed_and_start_agent, opts}, state) do
    # TODO: Reverting this check breaks tests; why?
    #
    #unless Enum.all?(mandatory_config_files(), &File.exists?/1) do
      _ = seed_config(opts)
    #end
    
    _ = start_agent()

    {:noreply, state}
  end

  def seed_config(opts) do
    seed_agent_config(opts)
    seed_standard_config(opts)

    [ &:snmpa_conf.write_community_config/2,
      &:snmpa_conf.write_usm_config/2,
      &:snmpa_conf.write_context_config/2,
      &:snmpa_conf.write_notify_config/2,

    ] |> Enum.map(fn fun -> :ok = fun.('snmp/agent', []) end)
  end

  defp do_seed_config(opts, default_opts, config_fun, write_fun) do
    :ok =
      default_opts
      |> Keyword.merge(opts)
      |> Enum.map(config_fun)
      |> write_fun.()
  end

  def seed_agent_config(agent_opts \\ [])
  def seed_agent_config(agent_opts) do
    config_fun = fn {k, v} -> :snmpa_conf.agent_entry(k, v) end
     write_fun = &:snmpa_conf.write_agent_config('snmp/agent', &1)

    [ intAgentTransports: [
        transportDomainUdpIpv4: {127,0,0,1},
        transportDomainUdpIpv6: {0,0,0,0,0,0,0,1}
      ],
      snmpEngineID: 'snmp_discovery_agent_engine',
      intAgentUDPPort: 6000,
      snmpEngineMaxMessageSize: 484,
    ] |> do_seed_config(agent_opts, config_fun, write_fun)

    config = :snmpa_conf.read_agent_config('snmp/agent')

    :ok = Logger.info("SNMP agent.conf created - #{inspect config}")
  end

  def seed_standard_config(standard_opts \\ [])
  def seed_standard_config(standard_opts) do
    config_fun = fn {k, v} -> :snmpa_conf.standard_entry(k, v) end
     write_fun = &:snmpa_conf.write_standard_config('snmp/agent', &1)

    [ sysName: 'Discovery agent',
      sysDescr: 'Discovery agent',
      sysContact: '',
      sysLocation: '',
      sysObjectID: [3,6,1,4,1,193,19],
      sysServices: 72,
      snmpEnableAuthenTraps: :disabled,
    ] |> do_seed_config(standard_opts, config_fun, write_fun)

    config = :snmpa_conf.read_standard_config('snmp/agent')

    :ok = Logger.info("SNMP standard.conf created - #{inspect config}")
  end

  def start_agent() do
    :ok = Logger.info("Starting snmp agent...")

    result =
      [ agent_type: :master,
        discovery: [
          originating: [enable: true],
          terminating: [enable: true]
        ],
        db_dir: 'snmp/agent/db',
        db_init_error: :create_db_and_dir,
        config: [dir: 'snmp/agent'],

      ] |> :snmpa_supervisor.start_master_sup

    case result do
      {:ok, _} ->
        nil

      {:error, {:already_started, _}} ->
        nil
    end

    configure_discovery()
  end

  def configure_discovery do
    {:ok, _} =
      :snmp_view_based_acm_mib.add_access(
        'discovery_group',
        '',
        :usm,
        :noAuthNoPriv,
        :exact,
        'discovery',
        'discovery',
        'discovery'
      )

    {:ok, _} =
      :snmp_view_based_acm_mib.add_sec2group(:usm, '', 'discovery_group')

    {:ok, _} =
      :snmp_view_based_acm_mib.add_view_tree_fam(
        'discovery',
        [1,3,6,1],
        :included,
        :null
      )

    {:ok, _} =
      :snmp_target_mib.add_params(
        'discovery_params',
        :v3,
        :usm,
        '',
        :noAuthNoPriv
      )
  end

  def discover_engine_id(uri, opts \\ [])
  def discover_engine_id(uri, opts) do
    clean_opts = Enum.reject(opts, fn({_k, v}) -> is_nil(v) end)

    GenServer.call(__MODULE__, {:discover_engine_id, uri, clean_opts})
  end

  def handle_call({:discover_engine_id, uri, opts_input}, _from, state) do
    default_opts = [
      port: uri.port || 161,
      transport: :transportDomainUdpIpv4,
      timeout: 2000,
      notification: :coldStart,
    ]

    opts = Keyword.merge(default_opts, opts_input)
    ip_string = String.replace(uri.host, ".", "_")
    agent_name = to_charlist "discovery_agent_#{ip_string}"
    erl_ip_address =
      uri.host
      |> NetAddr.ip
      |> NetAddr.netaddr_to_list

    {:ok, _} =
      :snmp_target_mib.add_addr(
        agent_name,
        opts[:transport],
        {erl_ip_address, uri.port},
        opts[:timeout],
        0,
        '',
        'discovery_params',
        '',
        [],
        2048
      )

    {:ok, engine_id} = :snmpa.discovery(agent_name, opts[:notification])

    {:reply, engine_id, state}
  end
end
