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

    # Since `topological_sort` does not guarantee an order
    # on elements of antichains (which are, by definition,
    # without order), we sort them, here, for convenience.
    sorted_antichains =
      adjacencies
      |> topological_sort
      |> Enum.map(&Enum.sort/1)

    assert sorted_antichains == [
             [:b, :c, :e],
             [:a, :d],
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

    # Again, the indifference of `topological sort` to tests
    # causes us some difficulties, here. Should we ever wish
    # to test for cycles of length greater than 3, the
    # result of `topological_sort` should itself be revised.
    assert_raise RuntimeError,
      ~r"^detected cycle in subset: \[(:a, :b, :c|:b, :c, :a|:c, :a, :b)\]$",
      fn -> topological_sort(adjacencies) end

  end
end
