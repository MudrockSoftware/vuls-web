import Config

config :vulsweb, start_store: false

config :vulsweb, VulswebWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}, port: 4002],
  secret_key_base: "f22h893YJ77gfTQ6HzPMFgNgLK/g+qfwiNZ1DWyixhYWi0orZ5TZfOVtzMbRpmoJ",
  server: false

config :logger, level: :warning

config :phoenix, :plug_init_mode, :runtime

config :phoenix_live_view, enable_expensive_runtime_checks: true

config :phoenix, sort_verified_routes_query_params: true
