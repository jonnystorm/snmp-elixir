defmodule SNMP.Mixfile do
  use Mix.Project

  def project do
    [ app: :snmp_ex,
      version: "0.1.1",
      elixir: "~> 1.3",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      deps: deps(),
      dialyzer: [
        plt_add_apps: [
          :logger,
          :snmp,
          :netaddr_ex,
          :jds_math_ex,
          :linear_ex,
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

  defp is_later_than(version_string1, version_string2) do
    # This is a kludge, but I think it will do.
    #
    latest =
      [version_string1, version_string2]
      |> Enum.sort_by(fn string ->
        string
        |> String.split(~r/[^0-9]/, trim: true)
        |> Enum.map(&String.to_integer/1)
      end)
      |> List.last

    (latest == version_string1)
      && (version_string1 != version_string2)
  end

  defp get_applications(version) do
    # Support Elixir < 1.4
    #
    applications =
      [ :logger,
        :netaddr_ex,
      ]

    if version |> is_later_than("1.3.4") do
      [extra_applications: applications]
    else
      [applications: applications]
    end
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    # Specify extra applications you'll use from Erlang/Elixir
    [ env: [
        mib_cache: "/tmp/snmp_ex/mibs",
        mib_sources: ["/usr/share/snmp/mibs"],
      ],
    ] ++ get_applications(System.version)
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
    [ {:netaddr_ex, git: "https://github.com/jonnystorm/netaddr-elixir"},
    ]
  end
end
