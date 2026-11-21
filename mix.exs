defmodule Vulsweb.MixProject do
  use Mix.Project

  @version "0.1.0"

  def project do
    [
      app: :vulsweb,
      version: @version,
      description: "A web UI for vuls vulnerability scan results",
      package: [licenses: ["GPL-3.0-or-later"], maintainers: ["MUDROCK SOFTWARE LTD"]],
      elixir: "~> 1.17",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      aliases: aliases(),
      deps: deps(),
      releases: releases(),
      compilers: [:phoenix_live_view] ++ Mix.compilers(),
      listeners: [Phoenix.CodeReloader]
    ]
  end

  def application do
    [
      mod: {Vulsweb.Application, []},
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  # support/ holds the sample data generator (dev + test only).
  defp elixirc_paths(:test), do: ["lib", "support", "test/support"]
  defp elixirc_paths(:dev), do: ["lib", "support"]
  defp elixirc_paths(_), do: ["lib"]

  # Elixir/Erlang deps come from Hex. Frontend deps (tailwind, daisyui,
  # lucide-static, topbar, fonts) are installed with bun, see assets/package.json.
  defp deps do
    [
      {:phoenix, "~> 1.8.17"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_view, "~> 1.2.15"},
      {:phoenix_live_reload, "~> 1.2", only: :dev},
      {:lazy_html, ">= 0.1.0", only: :test},
      {:jason, "~> 1.2"},
      {:bandit, "~> 1.5"},
      {:burrito_ng, "~> 1.0", runtime: false}
    ]
  end

  # `MIX_ENV=prod mix release` produces single-file executables in
  # burrito_ng_out/. Pick a single target with BURRITO_NG_TARGET=linux_amd64.
  defp releases do
    [
      vulsweb: [
        steps: [:assemble, &BurritoNg.wrap/1],
        burrito_ng: [
          targets: [
            linux_amd64: [os: :linux, cpu: :x86_64],
            linux_arm64: [os: :linux, cpu: :aarch64]
          ]
        ]
      ]
    ]
  end

  defp aliases do
    [
      setup: ["deps.get", "assets.setup", "assets.build"],
      "assets.setup": ["cmd --cd assets bun install --frozen-lockfile"],
      "assets.build": ["compile", "cmd --cd assets bun run build"],
      "assets.deploy": ["cmd --cd assets bun run deploy", "phx.digest"],
      "vulsweb.build": ["assets.deploy", "release --overwrite"],
      precommit: ["compile --warnings-as-errors", "deps.unlock --unused", "format", "test"]
    ]
  end
end
