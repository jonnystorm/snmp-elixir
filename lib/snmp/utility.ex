defmodule SNMP.Utility do
  @moduledoc false

  @spec local_engine_id() :: <<_::40>>
  def local_engine_id, do: <<0x8000000006::8*5>>

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
  defp subtract_minimal_elements_from_poset(poset, adj_map) do
    poset
    |> Enum.flat_map(& Map.get(adj_map, &1, []))
    |> MapSet.new
  end

  defp _partition_poset_as_antichains_of_minimal_elements(poset, adj_map, acc) do
    if MapSet.size(poset) > 0 do
      next_poset = subtract_minimal_elements_from_poset(poset, adj_map)

      minimal_elements = MapSet.difference(poset, next_poset)

      if MapSet.size(minimal_elements) == 0 do
        raise RuntimeError, "detected cycle in subset: #{inspect MapSet.to_list(poset)}"
      end

      next_acc = [minimal_elements|acc]

      next_poset
      |> _partition_poset_as_antichains_of_minimal_elements(adj_map, next_acc)
    else
      acc
      |> Enum.map(&MapSet.to_list &1)
      |> Enum.reverse
    end
  end

  # Takes mappings of the form {a => [b, c, ...]} to mean a < b, a < c, ...
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
  @spec partition_poset_as_antichains_of_minimal_elements(%{term => [term]}) :: [[term], ...]
  def partition_poset_as_antichains_of_minimal_elements(adjacency_map) do
    adjacency_map
    |> Map.keys
    |> MapSet.new
    |> _partition_poset_as_antichains_of_minimal_elements(adjacency_map, [])
  end
end
