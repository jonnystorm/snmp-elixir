defmodule SNMP.Utility do
  @moduledoc false

  @spec get_local_engine_id() :: <<_::40>>
  def get_local_engine_id, do: <<0x8000000006::8*5>>
end
