defmodule SNMP.Utility.Test do
  use ExUnit.Case

  import SNMP.Utility

  # Takes a strict poset, here represented as a Hasse diagram,
  #
  #       a   d
  #      / \ /
  #     b   c    e
  #
  # to
  #
  #     [[b, c, e], [a, d]]
  #
  test """
      Partitions a strict poset as maximal antichains of
      minimal elements
  """ do
    adjacencies = %{:e => [], :b => [:d, :a], :c => [:a]}

    assert topological_sort(adjacencies) == [
             [:c, :b, :e],
             [:a, :d]
           ]
  end

  # Raises on
  #
  #     :a<----:c
  #       \     ^
  #        \    |
  #         '->:b
  #
  test "Raises when a cycle is detected" do
    adjacencies = %{:a => [:c], :b => [:a], :c => [:b]}

    error = assert_raise RuntimeError, fn ->
      topological_sort(adjacencies)
    end

    # Convert the error message into a list and sort it for comparison
    assert error.message =~ "detected cycle in subset: "
    cycle = error.message
            |> String.replace("detected cycle in subset: ", "")
            |> String.replace(~r/[\[\]]/, "")
            |> String.split(", ")
            |> Enum.map(fn s ->
              s
              |> String.replace(":", "")
              |> String.to_atom()
            end)
            |> Enum.sort()

    assert cycle == [:a, :b, :c]
  end
end
