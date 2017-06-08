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
    GenServer.cast(self(), {:seed_and_start_agent, opts})
    {:ok, []}
  end

  def handle_cast({:seed_and_start_agent, opts}, state) do
    mandatory_config_files = ["snmp/agent/agent.conf", "snmp/agent/standard.conf", "snmp/agent/usm.conf", "snmp/agent/community.conf"]
    is_seeded = Enum.all?(mandatory_config_files, &(File.exists?(&1)))
    unless is_seeded, do: seed_config(opts)
    {:ok, _} = start_agent()
    {:noreply, state}
  end

  def seed_config(opts) do
    seed_agent_config(opts)
    seed_standard_config(opts)
    :ok = :snmpa_conf.write_community_config('snmp/agent', [])
    :ok = :snmpa_conf.write_usm_config('snmp/agent', [])
    :ok = :snmpa_conf.write_context_config('snmp/agent', [])
    :ok = :snmpa_conf.write_notify_config('snmp/agent', [])
  end

  def seed_agent_config(opts) do
    opts = Keyword.merge([intAgentTransports: [transportDomainUdpIpv4: {127,0,0,1}, transportDomainUdpIpv6: {0,0,0,0,0,0,0,1}],
                                snmpEngineID: 'snmp_discovery_agent_engine',
                             intAgentUDPPort: 6000,
                    snmpEngineMaxMessageSize: 484], opts[:agent_config] || [])
    conf_items = Enum.map(opts, fn({key, value}) -> :snmpa_conf.agent_entry(key, value) end)

    :ok = :snmpa_conf.write_agent_config('snmp/agent', conf_items)
    :ok = Logger.info("SNMP agent.conf created - #{inspect :snmpa_conf.read_agent_config('snmp/agent')}")
  end

  def seed_standard_config(opts) do
    opts = Keyword.merge([sysName: 'Discovery agent',
                          sysDescr: 'Discovery agent',
                          sysContact: '',
                          sysLocation: '',
                          sysObjectID: [3,6,1,4,1,193,19],
                          sysServices: 72,
                          snmpEnableAuthenTraps: :disabled], opts[:standard_config] || [])
    conf_items = Enum.map(opts, fn({key, value}) -> :snmpa_conf.standard_entry(key, value) end)
    :ok = :snmpa_conf.write_standard_config('snmp/agent', conf_items)
    :ok = Logger.info("SNMP standard.conf created - #{inspect :snmpa_conf.read_standard_config('snmp/agent')}")
  end

  def start_agent() do
    :ok = Logger.info("Starting snmp agent...")
    args = [  agent_type: :master,
              discovery: [originating: [enable: true], terminating: [enable: true]],
              db_dir: 'snmp/agent/db',
              db_init_error: :create_db_and_dir,
              config: [ dir: 'snmp/agent' ],
           ]
    {:ok, _} = :snmpa_supervisor.start_master_sup(args)
    configure_discovery_config()
  end

  def configure_discovery_config do
    {:ok, _} = :snmp_view_based_acm_mib.add_access('discovery_group', '', :usm, :noAuthNoPriv, :exact, 'discovery', 'discovery', 'discovery')
    {:ok, _} = :snmp_view_based_acm_mib.add_sec2group(:usm, '', 'discovery_group')
    {:ok, _} = :snmp_view_based_acm_mib.add_view_tree_fam('discovery', [1,3,6,1], :included, :null)
    {:ok, _} = :snmp_target_mib.add_params('discovery_params', :v3, :usm, '', :noAuthNoPriv)
  end

  def find_engine_id(ip_address, opts \\ []) do
    GenServer.call(__MODULE__, {:discover_engine_id, ip_address, opts})
  end

  def handle_call({:discover_engine_id, ip_address, opts_input}, _from, state) when is_binary(ip_address) do
    ip_address_tuple = ip_address |> :binary.bin_to_list |> List.to_tuple
    handle_call({:discover_engine_id, ip_address_tuple, opts_input}, _from, state)
  end

  def handle_call({:discover_engine_id, ip_address, opts_input}, _from, state) do
    clean_opts = Enum.reject(opts_input, fn({_k, v}) -> is_nil(v) end)
    opts = Keyword.merge([port: 161, transport: :transportDomainUdpIpv4, timeout: 2000, notification: :coldStart], clean_opts)

    agent_name = "discovery_agent_#{Enum.join(Tuple.to_list(ip_address), "_")}" |> to_charlist
    {:ok, _} = :snmp_target_mib.add_addr(agent_name, opts[:transport],
                                        {ip_address, opts[:port]}, opts[:timeout], 0, '', 'discovery_params', '', [], 2048)

    {:ok, engine_id} = :snmpa.discovery(agent_name, opts[:notification])
    {:reply, engine_id, state}
  end

end