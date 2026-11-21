defmodule VulswebWeb.HealthController do
  use VulswebWeb, :controller

  @doc "Liveness/readiness probe: 200 once the results directory is readable."
  def show(conn, _params) do
    status = Vulsweb.Results.status()
    code = if status.state == :ready, do: 200, else: 503

    conn
    |> put_status(code)
    |> json(%{
      status: status.state,
      error: status[:error],
      files: status[:files],
      version: to_string(Application.spec(:vulsweb, :vsn))
    })
  end
end
