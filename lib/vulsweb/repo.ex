defmodule Vulsweb.Repo do
  use Ecto.Repo,
    otp_app: :vulsweb,
    adapter: Ecto.Adapters.Postgres
end
