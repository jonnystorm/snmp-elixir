defmodule SNMP.Crypto do
  @moduledoc false

  alias SNMP.Utility

  defp convert_password_to_intermediate_key(password, algorithm)
      when algorithm in [:md5, :sha]
  do
    data =
      password
      |> :binary.bin_to_list
      |> Stream.cycle
      |> Enum.take(1048576)

    :crypto.hash(algorithm, data)
  end

  defp localize_key(key, algorithm, engine_id)
      when algorithm in [:md5, :sha]
  do
    :crypto.hash(algorithm, "#{key}#{engine_id}#{key}")
  end

  @type password :: binary
  @type algorithm :: :md5 | :sha
  @type engine_id :: nil | binary

  @spec convert_password_to_key(password, algorithm, engine_id) :: [byte]
  def convert_password_to_key(password, algorithm, engine_id \\ nil)
  def convert_password_to_key(password, algorithm, engine_id)
      when algorithm in [:md5, :sha]
  do
    # Per RFC 3414, except use of localEngineID
    eid = engine_id || Utility.local_engine_id

    password
    |> convert_password_to_intermediate_key(algorithm)
    |> localize_key(algorithm, eid)
    |> :binary.bin_to_list
  end

end

defmodule SNMP.FakeCrypto do
  @moduledoc false

  @type password :: binary
  @type algorithm :: :md5 | :sha
  @type engine_id :: nil | binary

  @spec convert_password_to_key(password, algorithm, engine_id) :: [byte]
  def convert_password_to_key(password, algorithm, engine_id \\ nil)

  def convert_password_to_key("authpass", :md5, _),
    do: [167, 81, 201, 199, 42, 46, 137, 43, 22, 203, 114, 40, 128, 16, 162, 141]

  def convert_password_to_key("authpass", :sha, _),
    do: [39, 237, 111, 41, 161, 2, 149, 234, 127, 88, 178, 4, 216, 251, 186, 158, 31, 164, 184, 199]

  def convert_password_to_key("privpass", :md5, _),
    do: [168, 5, 187, 57, 237, 205, 61, 51, 50, 34, 208, 202, 37, 247, 158, 92]

  def convert_password_to_key("privpass", :sha, _),
    do: [118, 114, 155, 192, 136, 56, 159, 175, 97, 219, 216, 18, 76, 140, 159, 2]
end
