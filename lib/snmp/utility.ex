defmodule SNMP.Utility do
  @moduledoc false

  @spec get_local_engine_id() :: <<_::40>>
  def get_local_engine_id, do: <<0x8000000006::8*5>>

  defp _convert_dag_to_strict_poset(remaining, adj_map, acc) do
    if MapSet.size(remaining) > 0 do
      next_remaining =
        remaining
        |> Enum.flat_map(& Map.get(adj_map, &1, []))
        |> MapSet.new

      if MapSet.size(next_remaining) == MapSet.size(remaining) do
        list = MapSet.to_list remaining

        raise RuntimeError, "detected cycle in subgraph: #{inspect list}"
      end

      next_acc = [MapSet.difference(remaining, next_remaining) | acc]

      _convert_dag_to_strict_poset(next_remaining, adj_map, next_acc)
    else
      acc
      |> Enum.map(&MapSet.to_list &1)
      |> Enum.reverse
    end
  end

  @spec convert_dag_to_strict_poset(%{term => [term]}) :: [[term], ...]
  def convert_dag_to_strict_poset(adjacency_map) do
    adjacency_map
    |> Map.keys
    |> MapSet.new
    |> _convert_dag_to_strict_poset(adjacency_map, [])
  end
end
