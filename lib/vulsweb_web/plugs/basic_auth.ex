defmodule VulswebWeb.Plugs.BasicAuth do
  @moduledoc """
  Optional HTTP basic auth, enabled by VULSWEB_AUTH_USER / VULSWEB_AUTH_PASSWORD.
  """

  @behaviour Plug

  @impl true
  def init(opts), do: opts

  @impl true
  def call(conn, _opts) do
    case Application.get_env(:vulsweb, :basic_auth) do
      nil -> conn
      creds -> Plug.BasicAuth.basic_auth(conn, Keyword.put(creds, :realm, "vulsweb"))
    end
  end
end
