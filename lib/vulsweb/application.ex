defmodule Vulsweb.Application do
  @moduledoc false

  use Application
  require Logger

  @impl true
  def start(_type, _args) do
    keep_running_under_burrito()
    log_auth_mode()

    children =
      [
        Vulsweb.ParentWatch.maybe_child(),
        {Phoenix.PubSub, name: Vulsweb.PubSub},
        store_child(),
        VulswebWeb.Endpoint
      ]
      |> Enum.reject(&is_nil/1)

    Supervisor.start_link(children, strategy: :one_for_one, name: Vulsweb.Supervisor)
  end

  # The burrito_ng wrapper boots the release through `elixir start_cli`, and
  # Kernel.CLI halts the VM as soon as it has processed argv (unless started
  # with --no-halt). It runs `System.at_exit/1` hooks first, so park a clean
  # exit there to keep serving. Errors (non-zero status) still halt, and
  # SIGTERM / init:stop shut down normally since they don't go through here.
  defp keep_running_under_burrito do
    if System.get_env("__BURRITO_NG") == "1" do
      System.at_exit(fn
        0 -> Process.sleep(:infinity)
        _status -> :ok
      end)
    end
  end

  defp log_auth_mode do
    case Application.get_env(:vulsweb, :basic_auth) do
      nil ->
        Logger.info(
          "basic auth disabled (set VULSWEB_AUTH_USER and VULSWEB_AUTH_PASSWORD to enable)"
        )

      creds ->
        Logger.info("basic auth enabled for user #{inspect(creds[:username])}")
    end
  end

  defp store_child do
    if Application.get_env(:vulsweb, :start_store, true) do
      {Vulsweb.Results.Store,
       dir: Application.fetch_env!(:vulsweb, :results_dir),
       interval: Application.get_env(:vulsweb, :refresh_interval, 15_000)}
    end
  end

  @impl true
  def config_change(changed, _new, removed) do
    VulswebWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
