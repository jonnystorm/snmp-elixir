defmodule SNMPTest do
  use ExUnit.Case
  doctest SNMP

  test "RFC 3414 A.3.1 - Password to Key Sample Results using MD5" do
    password = "maplesyrup"
    engine_id = <<0x000000000000000000000002::8*12>>
    result = :binary.bin_to_list <<0x526f5eed9fcce26f8964c2930787d82b::8*16>>

    assert SNMP.convert_password_to_key(password, :md5, engine_id) == result
  end

  test "RFC 3414 A.3.2 - Password to Key Sample Results using SHA" do
    password = "maplesyrup"
    engine_id = <<0x000000000000000000000002::8*12>>
    result = :binary.bin_to_list <<0x6695febc9288e36282235fc7151f128497b38f3f::8*20>>

    assert SNMP.convert_password_to_key(password, :sha, engine_id) == result
  end
end
