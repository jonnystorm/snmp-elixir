# This Source Code Form is subject to the terms of the
# Mozilla Public License, v. 2.0. If a copy of the MPL was
# not distributed with this file, You can obtain one at
# http://mozilla.org/MPL/2.0/.

defmodule SNMP.MIB do
  @moduledoc """
  Functions for working with SNMP MIBs.
  """

  alias SNMP.Utility

  require Logger

  # http://erlang.org/doc/apps/snmp/snmp_mib_compiler.html#id77861
  defp builtin_mibs do
    ~w(SNMPv2-SMI
       RFC-1215
       RFC-1212
       SNMPv2-TC
       SNMPv2-CONF
       RFC1155-SMI
    )
  end

  defp get_obsolete_mib_rfc_tuple(mib_name) do
    %{
      "IPV6-MIB" =>
        {"RFC 8096", "https://tools.ietf.org/html/rfc8096"},
      "IPV6-TC" =>
        {"RFC 8096", "https://tools.ietf.org/html/rfc8096"},
      "IPV6-ICMP-MIB" =>
        {"RFC 8096", "https://tools.ietf.org/html/rfc8096"},
      "IPV6-TCP-MIB" =>
        {"RFC 8096", "https://tools.ietf.org/html/rfc8096"},
      "IPV6-UDP-MIB" =>
        {"RFC 8096", "https://tools.ietf.org/html/rfc8096"}
    }[String.upcase(mib_name)]
  end

  defp is_obsolete_mib(mib_name),
    do: get_obsolete_mib_rfc_tuple(mib_name) != nil

  defp exclude_builtin_mibs(mibs) do
    Enum.filter(mibs, &(&1 not in builtin_mibs()))
  end

  defp get_imports_from_lines(lines) do
    lines
    |> Stream.filter(&String.contains?(&1, "FROM"))
    |> Stream.flat_map(fn line ->
      mib_import =
        ~r/\s?FROM\s+([^\s;]+)/
        |> Regex.run(line, capture: :all_but_first)

      mib_import || []
    end)
    |> Enum.to_list()
  end

  defp _get_imports([], acc), do: acc

  defp _get_imports([mib_file | rest], acc) do
    imports =
      try do
        mib_file
        |> File.stream!()
        |> get_imports_from_lines
        |> exclude_builtin_mibs
        |> Stream.map(fn name ->
          Path.join(Path.dirname(mib_file), "#{name}.mib")
        end)
        |> Enum.map(&{mib_file, &1})
      rescue
        File.Error ->
          :ok =
            Logger.debug(
              "Unable to find MIB file: #{
                inspect(mib_file)
              }"
            )

          [{mib_file, []}]
      end

    _get_imports(rest, Enum.concat(imports, acc))
  end

  defp get_imports(mib_files) when is_list(mib_files),
    do: _get_imports(mib_files, [])

  @type mib_file :: String.t()
  @type include_paths :: [String.t()]

  @doc """
  Compile the MIB in `mib_file` with includes from
  `include_paths`.
  """
  @spec compile(mib_file, include_paths) ::
          {:ok, term}
          | {:error, term}
  def compile(mib_file, include_paths) do
    outdir = Path.dirname(mib_file)
    erl_outdir = :binary.bin_to_list(outdir)
    erl_mib_file = :binary.bin_to_list(mib_file)

    erl_include_paths =
      Enum.map(
        include_paths,
        &:binary.bin_to_list("#{&1}/")
      )

    options = [
      :relaxed_row_name_assign_check,
      warnings: false,
      verbosity:
        Application.get_env(
          :snmp_ex,
          :snmpc_verbosity,
          "silence"
        ),
      group_check: false,
      i: erl_include_paths,
      outdir: erl_outdir
    ]

    mib_name = Path.basename(mib_file, ".mib")

    if is_obsolete_mib(mib_name) do
      {rfc, link} = get_obsolete_mib_rfc_tuple(mib_name)

      :ok =
        Logger.warn(
          "Compiling obsolete MIB #{inspect(mib_name)}... This may not work. Please see #{
            rfc
          } at #{link} for details"
        )
    end

    case :snmpc.compile(erl_mib_file, options) do
      {:error, {:invalid_file, _}} = error ->
        :ok =
          Logger.debug(
            "Unable to compile MIB #{inspect(mib_file)}: not a valid file"
          )

        error

      {:error, {:invalid_option, option}} = error ->
        :ok =
          Logger.debug(
            "Unable to compile MIB #{inspect(mib_file)} with invalid option #{
              inspect(option)
            }"
          )

        error

      {:error, :compilation_failed} = error ->
        :ok =
          Logger.debug(
            "Unable to compile MIB file #{
              inspect(mib_file)
            }"
          )

        error

      other ->
        other
    end
  end

  defp list_files_with_mib_extension(paths) do
    Enum.flat_map(paths, fn path ->
      path
      |> File.ls!()
      |> Stream.map(&Path.join(path, &1))
      |> Enum.filter(&String.ends_with?(&1, ".mib"))
    end)
  end

  defp convert_imports_to_adjacencies(imports),
    do: Enum.group_by(imports, &elem(&1, 1), &elem(&1, 0))

  defp order_imports_by_dependency_chains(adjacency_map),
    do: Utility.topological_sort(adjacency_map)

  @type mib_dir :: String.t()

  @doc """
  Compile all .mib files in `mib_dirs`.
  """
  @spec compile_all(mib_dir | [mib_dir, ...]) ::
          [{mib_file, {:ok, term} | {:error, term}}, ...]
  def compile_all(mib_dirs) when is_list(mib_dirs) do
    mib_dirs
    |> list_files_with_mib_extension
    |> get_imports
    |> convert_imports_to_adjacencies
    |> order_imports_by_dependency_chains
    |> List.flatten()
    |> Enum.map(&{&1, compile(&1, mib_dirs)})
  end

  def compile_all(mib_dir),
    do: compile_all([mib_dir])
end
