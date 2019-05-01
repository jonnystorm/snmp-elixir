defmodule SNMP.Mixfile do
  use Mix.Project

  def project do
    [ app: :snmp_ex,
      version: "0.2.0",
      elixir: "~> 1.7",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      dialyzer: [
        plt_add_apps: [
          :logger,
          :snmp,
          :netaddr_ex,
        ],
        ignore_warnings: "dialyzer.ignore",
        flags: [
          :unmatched_returns,
          :error_handling,
          :race_conditions,
          :underspecs,
        ],
      ],
    ]
  end

  def application do
    [ extra_applications: [
        :logger,
        :snmp,
      ],
      env: [
        timeout: 5000,
        max_repetitions: 10,
        engine_discovery_timeout: 1000,
        mib_cache:      "priv/snmp/mibs",
        snmp_conf_dir:  "priv/snmp/conf",
        snmpm_conf_dir: "priv/snmp",
        mib_sources: [
          "/usr/share/snmp/mibs",
        ],
      ],
      mod: {SNMP, []},
    ]
  end

  defp deps do
    [ {:netaddr_ex, "~> 1.0.5"},
    ]
  end

  defp description do
    "An SNMP client library for Elixir, wrapping the Erlang OTP SNMP API and Logic"
  end

    defp package do
    [ licenses: ["Mozilla Public License 2.0"],
      links: %{
        "GitHub" => "https://github.com/jonnystorm/snmp-elixir",
      },
    ]
  end


end
