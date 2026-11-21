import Config

# Assets are built by bun (see assets/package.json).
config :vulsweb, VulswebWeb.Endpoint,
  http: [ip: {127, 0, 0, 1}],
  check_origin: false,
  code_reloader: true,
  debug_errors: true,
  secret_key_base: "8edbFWFnejSvRbT8tO7FlzhAM1n9O4UkYGI/iL61of1THYTXe6MHeSBuC4waQ7G+",
  watchers: [
    bun: ["run", "watch:js", cd: Path.expand("../assets", __DIR__)],
    bun: ["run", "watch:css", cd: Path.expand("../assets", __DIR__)]
  ]

config :vulsweb, dev_routes: true

config :logger, :default_formatter, format: "[$level] $message\n"

config :phoenix, :stacktrace_depth, 20
config :phoenix, :plug_init_mode, :runtime

config :phoenix_live_view,
  debug_heex_annotations: true,
  debug_attributes: true,
  enable_expensive_runtime_checks: true
