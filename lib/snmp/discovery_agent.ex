defmodule SNMP.DiscoveryAgent do

  @moduledoc """
  Provides abstractions to SNMP engine discovery through
  snmp agent
  """

  use GenServer
  require Logger

  def start_link(state \\ [], opts0 \\ []) do
    opts = [{:name, __MODULE__}|opts0]

    GenServer.start_link(__MODULE__, state, opts)
  end

  def init(opts) do
    _ =
      GenServer.cast(self(), {:seed_and_start_agent, opts})

    {:ok, []}
  end

  defp agent_dir do
    :snmp_ex
    |> Application.get_env(:snmp_conf_dir)
    |> Path.expand
    |> Path.join("agent")
  end

  def handle_cast({:seed_and_start_agent, opts}, state) do
    agent_dir()
    |> Path.join("db")
    |> File.mkdir_p!

    _ =
      [ "#{agent_dir()}/agent.conf",
        "#{agent_dir()}/standard.conf",
        "#{agent_dir()}/usm.conf",
        "#{agent_dir()}/community.conf",

      ] |> Enum.map(&File.touch!/1)

    _ = seed_config(opts)
    _ = start_agent()

    {:noreply, state}
  end

  def seed_config(opts) do
    seed_agent_config    opts
    seed_standard_config opts

    [ &:snmpa_conf.write_community_config/2,
      &:snmpa_conf.write_usm_config/2,
      &:snmpa_conf.write_context_config/2,
      &:snmpa_conf.write_notify_config/2,

    ] |> Enum.map(fn fun ->
      :ok = fun.('#{agent_dir()}', [])
    end)
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
    config_fun =
      fn {k, v} -> :snmpa_conf.agent_entry(k, v) end

    write_fun =
      &:snmpa_conf.write_agent_config('#{agent_dir()}', &1)

    init_engine_id =
      :binary.bin_to_list SNMP.Utility.local_engine_id

    [ intAgentTransports: [
        transportDomainUdpIpv4: {127,0,0,1},
        transportDomainUdpIpv6: {0,0,0,0,0,0,0,1}
      ],
      snmpEngineID: init_engine_id,
      intAgentUDPPort: 6000,
      snmpEngineMaxMessageSize: 484,

    ] |> do_seed_config(agent_opts, config_fun, write_fun)

    config =
      :snmpa_conf.read_agent_config('#{agent_dir()}')

    :ok = Logger.info("SNMP agent.conf created - #{inspect config}")
  end

  def seed_standard_config(standard_opts \\ [])
  def seed_standard_config(standard_opts) do
    config_fun =
      fn {k, v} -> :snmpa_conf.standard_entry(k, v) end

     write_fun =
       &:snmpa_conf.write_standard_config('#{agent_dir()}', &1)

    [ sysName: 'Discovery agent',
      sysDescr: 'Discovery agent',
      sysContact: '',
      sysLocation: '',
      sysObjectID: [3,6,1,4,1,193,19],
      sysServices: 72,
      snmpEnableAuthenTraps: :disabled,

    ] |> do_seed_config(standard_opts, config_fun, write_fun)

    config =
      :snmpa_conf.read_standard_config('#{agent_dir()}')

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
        db_dir: '#{agent_dir()}/db',
        db_init_error: :create_db_and_dir,
        config: [dir: '#{agent_dir()}'],

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
      :snmp_view_based_acm_mib.add_sec2group(
        :usm,
        '',
        'discovery_group'
      )

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

  @type uri  :: URI.t
  @type opts :: Keyword.t

  @type engine_id :: charlist()

  @spec discover_engine_id(uri, opts)
    :: {:ok, engine_id}
     | {:error, any}
  def discover_engine_id(uri, opts \\ [])
  def discover_engine_id(uri, opts) do
    clean_opts =
      Enum.reject(opts, fn({_k, v}) -> is_nil(v) end)

    msg = {:discover_engine_id, uri, clean_opts}

    GenServer.call(__MODULE__, msg, 60_000)
  end

  def handle_call(
    {:discover_engine_id, uri, opts_input},
    _from,
    state
  ) do
    # OTP multiplies the below timeout by 10, then doubles
    # it for each successive retry. Consequently, given an
    # initial timeout of 100, OTP will first use a timeout
    # of 1000, followed by a timeout of 2000, followed by a
    # timeout of 4000, and so on. Whether this is all in
    # milliseconds is unclear. It probably is milliseconds.
    #
    # For proof, please see https://github.com/jonnystorm/otp/blob/f6a862dcc515d8500097aac2b0f84e501d8d0968/lib/snmp/src/agent/snmpa_trap.erl#L631-L677
    #
    default_opts = [
      port:         uri.port || 161,
      transport:    :transportDomainUdpIpv4,
      timeout:      1000,
      retries:      2,
      notification: :coldStart,
    ]

    opts       = Keyword.merge(default_opts, opts_input)
    timeout    = trunc(opts[:timeout] / 10)
    ip_string  = String.replace(uri.host, ".", "_")
    agent_name = to_charlist "discovery_agent_#{ip_string}"
    erl_ip_address =
      uri.host
      |> NetAddr.ip
      |> NetAddr.netaddr_to_list

    {:ok, _} =
      :snmp_target_mib.add_addr(
        agent_name,
        opts[:transport],
        {erl_ip_address, opts[:port]},
        timeout,
        opts[:retries],
        '',
        'discovery_params',
        '',
        [],
        2048
      )

    result =
      :snmpa.discovery(agent_name, opts[:notification])

    {:reply, result, state}
  end
end
