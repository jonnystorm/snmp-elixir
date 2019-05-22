defmodule SNMP.Credential do
  @type snmp_credential ::
          Community.t()
          | USM.t()

  defmodule Community do
    defstruct [
      :version,
      :sec_model,
      :community
    ]

    @type t ::
            %__MODULE__{
              version: :v1 | :v2,
              sec_model: :v1 | :v2c,
              community: [byte]
            }
  end

  defmodule USM do
    defstruct version: :v3,
              sec_model: :usm,
              sec_level: nil,
              sec_name: [],
              auth: nil,
              auth_pass: nil,
              priv: nil,
              priv_pass: nil

    @type t ::
            %__MODULE__{
              version: :v3,
              sec_model: :usm,
              sec_level:
                :noAuthNoPriv
                | :authNoPriv
                | :authPriv,
              sec_name: [byte],
              auth: nil | :md5 | :sha,
              auth_pass: nil | [byte],
              priv: nil | :des | :aes,
              priv_pass: nil | [byte]
            }
  end

  @doc """
  Returns a keyword list containing the given SNMPv1/2c/3
  credentials.

  ## Example

      iex> SNMP.Credential.login([:v1, "public"])
      %SNMP.Community{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.Credential.login([:v2c, "public"])
      %SNMP.Community{version: :v2, sec_model: :v2c, community: 'public'}

      iex> SNMP.Credential.login([:v3, :no_auth_no_priv, "user"])
      %SNMP.USM{sec_level: :noAuthNoPriv, sec_name:  'user'}

      iex> SNMP.Credential.login([:v3, :auth_no_priv, "user", :md5, "authpass"])
      %SNMP.USM{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
      }

      iex> SNMP.Credential.login([:v3, :auth_no_priv, "user", :sha, "authpass"])
      %SNMP.USM{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
      }

      iex> SNMP.Credential.login([:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass"])
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.Credential.login([:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass"])
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.Credential.login([:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass"])
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

      iex> SNMP.Credential.login([:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass"])
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

  """
  @spec login([atom | String.t()]) ::
          snmp_credential
          | no_return
  def login(args) when is_list(args) do
    case args do
      [:v1, _] ->
        apply(&login/2, args)

      [:v2c, _] ->
        apply(&login/2, args)

      [:v3, :no_auth_no_priv, _] ->
        apply(&login/3, args)

      [:v3, :auth_no_priv, _, _, _] ->
        apply(&login/5, args)

      [:v3, :auth_priv, _, _, _, _, _] ->
        apply(&login/7, args)
    end
  end

  @doc """
  Returns a keyword list containing the given SNMPv1/2c
  community.

  ## Example

      iex> SNMP.Credential.login(:v1, "public")
      %SNMP.Community{version: :v1, sec_model: :v1, community: 'public'}

      iex> SNMP.Credential.login(:v2c, "public")
      %SNMP.Community{version: :v2, sec_model: :v2c, community: 'public'}

  """
  @spec login(:v1 | :v2c, String.t()) ::
          snmp_credential
          | no_return
  def login(version, community)

  def login(:v1, community) do
    %Community{
      version: :v1,
      sec_model: :v1,
      community: :binary.bin_to_list(community)
    }
  end

  def login(:v2c, community) do
    %Community{
      version: :v2,
      sec_model: :v2c,
      community: :binary.bin_to_list(community)
    }
  end

  @doc """
  Returns a keyword list containing the given SNMPv3
  noAuthNoPriv credentials.

  ## Example

      iex> SNMP.Credential.login(:v3, :no_auth_no_priv, "user")
      %SNMP.USM{sec_level: :noAuthNoPriv, sec_name: 'user'}

  """
  @spec login(:v3, :no_auth_no_priv, String.t()) ::
          snmp_credential
          | no_return
  def login(version, sec_level, sec_name)

  def login(:v3, :no_auth_no_priv, sec_name),
    do: %USM{
      sec_level: :noAuthNoPriv,
      sec_name: :binary.bin_to_list(sec_name)
    }

  @doc """
  Returns a keyword list containing the given SNMPv3
  authNoPriv credentials.

  ## Example

      iex> SNMP.Credential.login(:v3, :auth_no_priv, "user", :md5, "authpass")
      %SNMP.USM{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
      }

      iex> SNMP.Credential.login(:v3, :auth_no_priv, "user", :sha, "authpass")
      %SNMP.USM{
        sec_level: :authNoPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
      }

  """
  @spec login(
          :v3,
          :auth_no_priv,
          String.t(),
          :md5 | :sha,
          String.t()
        ) ::
          snmp_credential
          | no_return
  def login(
        version,
        sec_level,
        sec_name,
        auth_proto,
        auth_pass
      )

  def login(
        :v3,
        :auth_no_priv,
        sec_name,
        auth_proto,
        auth_pass
      )
      when auth_proto in [:md5, :sha] do
    %USM{
      sec_level: :authNoPriv,
      sec_name: :binary.bin_to_list(sec_name),
      auth: auth_proto,
      auth_pass: :binary.bin_to_list(auth_pass)
    }
  end

  @doc """
  Returns `t:snmp_credential/0` containing the given SNMPv3
  authPriv credentials.

  ## Examples

      iex> SNMP.Credential.login(:v3, :auth_priv, "user", :md5, "authpass", :des, "privpass")
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.Credential.login(:v3, :auth_priv, "user", :sha, "authpass", :des, "privpass")
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :des,
        priv_pass: 'privpass',
      }

      iex> SNMP.Credential.login(:v3, :auth_priv, "user", :md5, "authpass", :aes, "privpass")
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :md5,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

      iex> SNMP.Credential.login(:v3, :auth_priv, "user", :sha, "authpass", :aes, "privpass")
      %SNMP.USM{
        sec_level: :authPriv,
        sec_name:  'user',
        auth:      :sha,
        auth_pass: 'authpass',
        priv:      :aes,
        priv_pass: 'privpass',
      }

  """
  @spec login(
          :v3,
          :auth_priv,
          String.t(),
          :md5 | :sha,
          String.t(),
          :des | :aes,
          String.t()
        ) ::
          snmp_credential
          | no_return
  def login(
        version,
        sec_level,
        sec_name,
        auth_proto,
        auth_pass,
        priv_proto,
        priv_pass
      )

  def login(
        :v3,
        :auth_priv,
        sec_name,
        auth_proto,
        auth_pass,
        priv_proto,
        priv_pass
      )
      when auth_proto in [:md5, :sha] and
             priv_proto in [:des, :aes] do
    # http://erlang.org/doc/man/snmpm.html#register_usm_user-3

    %USM{
      sec_level: :authPriv,
      sec_name: :binary.bin_to_list(sec_name),
      auth: auth_proto,
      auth_pass: :binary.bin_to_list(auth_pass),
      priv: priv_proto,
      priv_pass: :binary.bin_to_list(priv_pass)
    }
  end
end
