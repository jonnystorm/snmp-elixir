# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SNMP.MIB do
  @moduledoc """
  Functions for working with SNMP MIBs.
  """

  alias SNMP.Utility

  require Logger

  # http://erlang.org/doc/apps/snmp/snmp_mib_compiler.html#id77861
  defp builtin_mibs,
    do: ~w(SNMPv2-SMI RFC-1215 RFC-1212 SNMPv2-TC SNMPv2-CONF RFC1155-SMI)

  defp exclude_builtin_mibs(mibs) do
    Enum.filter(mibs, & not &1 in builtin_mibs())
  end

  defp get_imports_from_lines(lines) do
    lines
    |> Stream.filter(&String.contains?(&1, "FROM"))
    |> Stream.flat_map(fn line ->
      Regex.run(~r/\s?FROM\s+([^\s;]+)/, line, capture: :all_but_first) || []
    end)
    |> Enum.to_list
  end

  defp _get_imports([], acc), do: acc
  defp _get_imports([mib_file|rest], acc) do
    imports =
      try do
        mib_file
        |> File.stream!
        |> get_imports_from_lines
        |> exclude_builtin_mibs
        |> Stream.map(&Path.join(Path.dirname(mib_file), "#{&1}.mib"))
        |> Enum.map(& {mib_file, &1})

      rescue
        File.Error ->
          :ok = Logger.error("Unable to find MIB file: #{inspect mib_file}")

          [{mib_file, []}]
      end

    _get_imports(rest, Enum.concat(imports, acc))
  end

  defp get_imports(mib_files) when is_list(mib_files),
    do: _get_imports(mib_files, [])

  @type mib_file :: String.t
  @type include_paths :: [String.t]

  @doc """
  Compiles the MIB in `mib_file` with includes from `include_paths`.
  """
  @spec compile(mib_file, include_paths) :: {:ok, term} | {:error, term}
  def compile(mib_file, include_paths) do
    erl_mib_file = :binary.bin_to_list mib_file
    erl_include_paths = Enum.map(include_paths, &:binary.bin_to_list("#{&1}/"))
    outdir = :binary.bin_to_list Path.dirname(mib_file)
    options = [
      warnings: false,
      #:warnings_as_errors,
      i: erl_include_paths,
      outdir: outdir,
    ]

    case :snmpc.compile(erl_mib_file, options) do
      {:error, {:invalid_file, _}} = error ->
        :ok = Logger.error("Unable to compile invalid MIB file: #{inspect mib_file}")

        error

      {:error, {:invalid_option, option}} = error ->
        :ok = Logger.error("Unable to compile MIB with invalid option: #{inspect option}")

        error

      other ->
        other
    end
  end

  defp list_files_with_mib_extension(paths) do
    Enum.flat_map(paths, fn path ->
      path
      |> File.ls!
      |> Stream.map(&Path.join(path, &1))
      |> Enum.filter(&String.ends_with?(&1, ".mib"))
    end)
  end

  defp convert_imports_to_adjacencies(imports),
    do: Enum.group_by(imports, &elem(&1, 1), &elem(&1, 0))

  defp order_imports_by_dependency_chains(adjacency_map),
    do: Utility.partition_poset_as_antichains_of_minimal_elements(adjacency_map)

  @type mib_dir :: String.t

  @doc """
  Compile all .mib files in `mib_dirs`.
  """
  @spec compile_all([mib_dir]) :: [{mib_file, {:ok, term} | {:error, term}}]
  def compile_all(mib_dirs) when is_list mib_dirs do
    # This doesn't handle subdirectories; may need to write find/2 later.
    mib_dirs
    |> list_files_with_mib_extension
    |> get_imports
    |> convert_imports_to_adjacencies
    |> order_imports_by_dependency_chains
    |> List.flatten
    |> Enum.map(&{&1, compile(&1, mib_dirs)})
  end

  @doc """
  Compile all .mib files in `mib_dir`.
  """
  @spec compile_all(mib_dir) :: [{mib_file, {:ok, term} | {:error, term}}]
  def compile_all(mib_dir),
    do: compile_all([mib_dir])
end
