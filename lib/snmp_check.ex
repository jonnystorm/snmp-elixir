defmodule SNMPCheck do
  @moduledoc false

  import SNMP

  # Trigger dialyzer success typing checks in SNMP API
  #
  def check do
    v2_cred = credential(%{community: "public"})
    req     =
      %{uri: URI.parse("snmp://192.0.2.1"),
        credential: v2_cred,
        varbinds: [%{oid: [1,3,6,1,2,1,1,5,0]}],
      }

    _ = request(req)
    _ = walk(req)

    _ = load_mib("some_mib")
    _ = resolve_object_name_to_oid([1,3,6])
    _ = resolve_object_name_to_oid(:sysName)

    _ = credential(%{sec_name: "admin"})

    _ = list_oid_to_string([1,3,6])
    _ = string_oid_to_list("1.3.6")
  end
end
