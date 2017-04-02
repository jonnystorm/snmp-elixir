defmodule SNMP.MIB.Test do
  use ExUnit.Case
  doctest SNMP.MIB

  import SNMP.MIB

  @moduletag :integrated

  @tmp_dir "test/mib_tmp"

  setup_all do
    File.mkdir! @tmp_dir
    File.cp_r! "test/fixtures/mibs", @tmp_dir

    on_exit fn ->
      File.rm_rf! @tmp_dir
    end
  end

  test "Compiles directory of SNMP MIBs (with extension .mib) without errors" do
    results = compile_all @tmp_dir

    assert Enum.all?(results, fn {_, {a, _}} -> a == :ok end)
  end
end
