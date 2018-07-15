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
  """
  do
    adjacencies =
      %{:e => [],
        :b => [:d, :a],
        :c => [:a],
      }

    assert topological_sort(adjacencies) ==
      [[:b, :c, :e], [:a, :d]]
  end

  # Raises on
  #
  #     :a<----:c
  #       \     ^
  #        \    |
  #         '->:b
  #
  test "Raises when a cycle is detected" do
    adjacencies =
      %{:a => [:c],
        :b => [:a],
        :c => [:b],
      }

    assert_raise RuntimeError,
      "detected cycle in subset: [:a, :b, :c]",
      fn -> topological_sort(adjacencies) end
  end
end
