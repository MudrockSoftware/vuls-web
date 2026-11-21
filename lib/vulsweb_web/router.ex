defmodule VulswebWeb.Router do
  use VulswebWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug VulswebWeb.Plugs.BasicAuth
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {VulswebWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
  end

  pipeline :export do
    plug VulswebWeb.Plugs.BasicAuth
  end

  # Unauthenticated, for container health checks.
  scope "/", VulswebWeb do
    get "/healthz", HealthController, :show
  end

  scope "/", VulswebWeb do
    pipe_through :export

    get "/export/cves.csv", ExportController, :cves
    get "/hosts/:host/export.csv", ExportController, :host
  end

  scope "/", VulswebWeb do
    pipe_through :browser

    live_session :default do
      live "/", DashboardLive
      live "/hosts/:host", HostLive
      live "/cves", CveIndexLive
      live "/cves/:cve_id", CveLive
    end
  end
end
