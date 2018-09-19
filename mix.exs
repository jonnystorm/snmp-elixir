defmodule SNMP.Mixfile do
  use Mix.Project

  def project do
    [
      app: :snmp_ex,
      version: "0.1.1",
      elixir: "~> 1.6",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      dialyzer: [
        plt_add_apps: [
          :logger,
          :snmp,
          :netaddr_ex,
          :jds_math_ex,
          :linear_ex
        ],
        ignore_warnings: "dialyzer.ignore",
        flags: [
          :unmatched_returns,
          :error_handling,
          :race_conditions,
          :underspecs
        ]
      ]
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [
      extra_applications: [
        :logger,
        :netaddr_ex
      ],
      env: [
        mib_sources: ["/usr/share/snmp/mibs"],
        mib_cache: "/tmp/snmp_ex/mibs",
        snmp_conf_dir: "/tmp/snmp_ex/conf",
        snmpm_conf_dir: "/tmp/snmp_ex",
        engine_discovery_timeout: 1000
      ]
    ]
  end

  # Dependencies can be Hex packages:
  #
  #   {:my_dep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:my_dep, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:netaddr_ex,
       git: "https://github.com/jonnystorm/netaddr-elixir"}
    ]
  end
end
