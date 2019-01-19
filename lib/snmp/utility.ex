defmodule SNMP.Utility do
  @moduledoc false

  @spec local_engine_id() :: <<_::40>>
  def local_engine_id,
    do: <<0x8000000006::8*5>>

  # Takes
  #
  #      a   d
  #     / \ /
  #    b   c    e
  #
  # and returns
  #
  #    {bce}
  #
  defp subtract_minimal_elements_from_poset(poset, adj_map)
  do
    poset
    |> Enum.flat_map(&Map.get(adj_map, &1, []))
    |> MapSet.new()
  end

  defp _topological_sort(poset, adj_map, acc) do
    if MapSet.size(poset) > 0 do
      next_poset =
        poset
        |> subtract_minimal_elements_from_poset(adj_map)

      minimal_elements =
        MapSet.difference(poset, next_poset)

      if MapSet.size(minimal_elements) == 0 do
        raise(
          RuntimeError,
          "detected cycle in subset: #{inspect(MapSet.to_list(poset))}"
        )
      end

      next_acc = [minimal_elements | acc]

      _topological_sort(next_poset, adj_map, next_acc)
    else
      acc
      |> Enum.map(&MapSet.to_list(&1))
      |> Enum.reverse()
    end
  end

  # Takes mappings of the form {a => [b, c, ...]} to mean
  # a < b, a < c, ...
  #
  # For the Hasse diagram
  #
  #    a   d
  #   / \ /
  #  b   c    e
  #
  # it returns
  #
  #    [[b, c, e], [a, d]]
  #
  @spec topological_sort(%{term => [term]})
    :: [[term], ...]
  def topological_sort(adjacency_map) do
    adjacency_map
    |> Map.keys()
    |> MapSet.new()
    |> _topological_sort(adjacency_map, [])
  end

  # Kludge to make snmp-elixir compile on 1.3.4 while
  # avoiding inevitable doom of `Enum.partition/2`
  #
  defmacrop separate_dirs_from_files(paths) do
    if System.version() =~ ~r/^1\.[0-3]\./ do
      quote bind_quoted: [paths: paths] do
        Enum.partition(
          paths,
          &(File.lstat!(&1).type == :directory)
        )
      end
    else
      quote bind_quoted: [paths: paths] do
        Enum.split_with(
          paths,
          &(File.lstat!(&1).type == :directory)
        )
      end
    end
  end

  defp _find_files_recursive([], _pattern, acc),
    do: Enum.sort(acc)

  defp _find_files_recursive([dir | rest], pattern, acc) do
    {new_dirs, files} =
      dir
      |> File.ls!()
      |> Enum.map(&Path.absname(&1, dir))
      |> separate_dirs_from_files

    next_acc =
      files
      |> Enum.filter(&String.match?(&1, pattern))
      |> Enum.concat(acc)

    next_dirs = new_dirs ++ rest

    _find_files_recursive(next_dirs, pattern, next_acc)
  end

  @type path      :: String.t()
  @type pattern   :: Regex.t()
  @type filepath  :: String.t()
  @type filepaths :: [filepath, ...] | []

  # Analogous to GNU find
  @spec find_files_recursive(path, pattern)
    :: filepaths
  def find_files_recursive(path, pattern \\ ~r//)

  def find_files_recursive(path, pattern) do
    if File.dir?(path) do
      _find_files_recursive([path], pattern, [])
    else
      if String.match?(path, pattern) do
        [path]
      else
        []
      end
    end
  end
end
