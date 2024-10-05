defmodule SNMP.Mixfile do
  use Mix.Project

  def project do
    [ app: :snmp_ex,
      version: "0.6.1",
      elixir: "~> 1.12",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      dialyzer: [
        plt_add_apps: [
          :logger,
          :netaddr_ex,
          :snmp,
        ],
        ignore_warnings: "dialyzer.ignore",
        flags: [
          :unmatched_returns,
          :error_handling,
          :underspecs,
        ],
      ],
    ]
  end

  def application do
    [ extra_applications: [
        :crypto,
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
    [ {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:netaddr_ex, "~> 1.3"},
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
