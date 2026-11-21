import Config

# Runtime configuration, read from the environment on every boot (including
# the single-file binary built with burrito_ng and the Docker image).
#
#   VULS_RESULTS_DIR      vuls results directory   (prod: /vuls/results, dev: sample/results)
#   VULSWEB_REFRESH       seconds between results directory scans (default 15)
#   VULSWEB_STALE_AFTER   hours after which a host's last scan is flagged stale (default 48)
#   VULSWEB_AUTH_USER     enable HTTP basic auth with this user ...
#   VULSWEB_AUTH_PASSWORD ... and this password
#   BIND / PORT           listen address (prod default 0.0.0.0:5111)
#   PHX_HOST              public host name, used for generated URLs (default localhost)
#   SECRET_KEY_BASE       cookie signing key (generated at boot when unset)

env = fn name, default ->
  case System.get_env(name) do
    nil -> default
    "" -> default
    value -> value
  end
end

int_env = fn name, default ->
  value = env.(name, nil)

  case value && Integer.parse(value) do
    nil -> default
    {int, ""} when int > 0 -> int
    _ -> raise "#{name} must be a positive integer, got: #{inspect(value)}"
  end
end

default_results_dir = if config_env() == :prod, do: "/vuls/results", else: "sample/results"

config :vulsweb,
  results_dir: Path.expand(env.("VULS_RESULTS_DIR", default_results_dir)),
  refresh_interval: int_env.("VULSWEB_REFRESH", 15) * 1000,
  stale_after_hours: int_env.("VULSWEB_STALE_AFTER", 48)

case {env.("VULSWEB_AUTH_USER", nil), env.("VULSWEB_AUTH_PASSWORD", nil)} do
  {nil, nil} ->
    config :vulsweb, :basic_auth, nil

  {user, password} when is_binary(user) and is_binary(password) ->
    config :vulsweb, :basic_auth, username: user, password: password

  _ ->
    raise "set both VULSWEB_AUTH_USER and VULSWEB_AUTH_PASSWORD to enable basic auth"
end

if config_env() == :dev do
  config :vulsweb, VulswebWeb.Endpoint,
    http: [port: int_env.("PORT", 4000)],
    live_reload: [
      web_console_logger: true,
      patterns: [
        ~r"priv/static/(?!uploads/).*\.(js|css|png|jpeg|jpg|gif|svg)$"E,
        ~r"lib/vulsweb_web/router\.ex$"E,
        ~r"lib/vulsweb_web/(controllers|live|components)/.*\.(ex|heex)$"E
      ]
    ]
end

if config_env() == :prod do
  bind = env.("BIND", "0.0.0.0")

  ip =
    case :inet.parse_address(String.to_charlist(bind)) do
      {:ok, ip} -> ip
      {:error, _} -> raise "BIND must be an IP address, got: #{inspect(bind)}"
    end

  # Sessions only carry the CSRF token, so a per-boot random key is fine;
  # set SECRET_KEY_BASE to keep sessions across restarts.
  secret_key_base =
    env.("SECRET_KEY_BASE", nil) || Base.encode64(:crypto.strong_rand_bytes(48))

  config :vulsweb, VulswebWeb.Endpoint,
    # Always serve: the binary and the container only run the web server.
    server: true,
    url: [host: env.("PHX_HOST", "localhost")],
    http: [ip: ip, port: int_env.("PORT", 5111)],
    # Accept LiveView connections from whatever host/IP the UI was opened on.
    check_origin: :conn,
    secret_key_base: secret_key_base
end
