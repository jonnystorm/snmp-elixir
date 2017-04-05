defmodule SNMP.Utility.Test do
  use ExUnit.Case

  import SNMP.Utility

  @doc """
  Takes

      :e

      :d
       \
        )=>:b
       /
      :a
       \
        `-> :c

  to

      [[:b,:c,:e], [:a, :d]]
  """
  test "Converts directed acyclic graph (DAG) to a strict poset" do
    adjacencies =
      %{:e => [],
        :b => [:d, :a],
        :c => [:a],
      }

    assert convert_dag_to_strict_poset(adjacencies) ==
      [[:b, :c, :e], [:a, :d]]
  end

  @doc """
  Raises on

      :d

      :a<----:c
        \     ^
         \    |
          '->:b
  """
  test "Raises when a cycle is detected" do
    adjacencies =
      %{:a => [:c],
        :b => [:a],
        :c => [:b],
      }

    assert_raise RuntimeError, "detected cycle in subgraph: [:a, :b, :c]", fn ->
      convert_dag_to_strict_poset(adjacencies)
    end
  end
end
