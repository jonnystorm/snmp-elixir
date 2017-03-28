# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

defmodule SNMP.MIB do
  @moduledoc """
  A library for working with SNMP MIBs.
  """

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

  defp _get_imports_recursive([], _dir, acc),
    do: Enum.uniq(acc)

  defp _get_imports_recursive([next_mib|rest], dir, acc) do
    # This is a hack. Later, we may need to protect against loops with a
    # partial ordering structure.
    mib_file = Path.join(dir, next_mib <> ".mib")

    try do
      rest
      |> Enum.concat(
        mib_file
        |> File.stream!
        |> get_imports_from_lines
        |> exclude_builtin_mibs
      ) |> _get_imports_recursive(dir, [next_mib|acc])

    rescue
      File.Error ->
        :ok = Logger.error("Unable to find MIB file: #{inspect mib_file}")

        _get_imports_recursive(rest, dir, acc)
    end
  end

  defp get_imports_recursive(mib_names, path) when is_list(mib_names),
    do: _get_imports_recursive(mib_names, path, [])

  defp get_imports_recursive(mib_name, path),
    do: _get_imports_recursive([mib_name], path, [])

  def compile(mib_file, import_path) do
    erl_import_path = :binary.bin_to_list import_path
    erl_mib_file = :binary.bin_to_list mib_file
    options = [i: [erl_import_path], outdir: erl_import_path]

    case :snmpc.compile(erl_mib_file, options) do
      {:error, {:invalid_file, _}} = error ->
        :ok = Logger.error("Unable to compile invalid file: #{inspect mib_file}")

        error

      {:error, {:invalid_option, _}} = error -> 
        :ok = Logger.error("Unable to compile with invalid import path: #{inspect import_path}")

        error

      other ->
        other
    end
  end

  @doc """
  Compile all .mib files in `mib_path`.
  """
  def compile_all(mib_path) do
    # This doesn't handle subdirectories; may need to write find/2 later.
    # This doesn't handle a separate list of import paths. Too hard right now.
    mib_path
    |> File.ls!
    |> Stream.filter(&String.ends_with?(&1, ".mib"))
    |> Enum.map(&Path.basename(&1, ".mib"))
    |> get_imports_recursive(mib_path)
    |> Enum.map(&Path.join(mib_path, "#{&1}.mib"))
    |> Enum.map(&compile(&1, mib_path))
  end
end
