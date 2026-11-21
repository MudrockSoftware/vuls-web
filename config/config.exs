# General application configuration. Runtime settings (results directory,
# listen address, auth, ...) are read from the environment in runtime.exs.
import Config

config :vulsweb,
  # Start the results indexer with the application (disabled in tests).
  start_store: true

config :vulsweb, VulswebWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: VulswebWeb.ErrorHTML, json: VulswebWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: Vulsweb.PubSub,
  live_view: [signing_salt: "2suZNAnB"]

config :logger, :default_formatter,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

config :phoenix, :json_library, Jason

import_config "#{config_env()}.exs"
