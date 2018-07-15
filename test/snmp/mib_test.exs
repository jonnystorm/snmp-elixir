defmodule SNMP.MIB.Test do
  use ExUnit.Case, async: false
  doctest SNMP.MIB

  import SNMP.MIB

  @moduletag :integrated

  @tmp_dir      "test/mib_tmp"
  @fixtures_dir "test/fixtures"

  setup do
    on_exit fn ->
      File.rm_rf! @tmp_dir
    end
  end

  test """
      Compiles all good and patched SNMP MIBs in directory
      without errors
  """
  do
    File.cp_r! "#{@fixtures_dir}/mibs", @tmp_dir

    results = compile_all @tmp_dir

    mib_files =
      Enum.map results,
        fn {f, _} -> :binary.bin_to_list(f) end

    assert Enum.all?(results, fn {_, {a, _}} -> a == :ok end)
    assert :snmpc.is_consistent(mib_files) == :ok
  end

  test "Fails to compile broken SNMP MIBs" do
    File.cp_r! "#{@fixtures_dir}/broken_mibs", @tmp_dir

    results = compile_all @tmp_dir

    assert Enum.all?(results, fn {_, {a, _}} -> a != :ok end)
  end
end
