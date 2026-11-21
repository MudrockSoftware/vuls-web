defmodule VulswebWeb.Layouts do
  @moduledoc """
  Layouts used by the application.
  """
  use VulswebWeb, :html

  embed_templates "layouts/*"

  @doc """
  Renders the app layout.

      <Layouts.app flash={@flash} active={:dashboard} status={@status}>
        ...
      </Layouts.app>
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :active, :atom, default: nil, doc: "highlighted nav item (:dashboard | :cves)"
  attr :status, :map, default: nil, doc: "indexer status from Vulsweb.Results.status/0"
  slot :inner_block, required: true

  def app(assigns) do
    ~H"""
    <div class="flex min-h-dvh flex-col">
      <header class="sticky top-0 z-40 border-b border-base-300 bg-base-100/95 backdrop-blur-sm supports-backdrop-filter:bg-base-100/85">
        <div class="site-container flex h-16 items-center justify-between gap-6">
          <div class="flex items-center gap-8">
            <.link navigate={~p"/"} class="inline-flex items-center gap-2.5">
              <span class="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-content">
                <.icon name="lucide-shield-check" class="size-5" />
              </span>
              <span class="text-lg font-bold tracking-tight">vulsweb</span>
            </.link>
            <nav class="hidden items-center gap-1 sm:flex">
              <.nav_link navigate={~p"/"} active={@active == :dashboard}>Dashboard</.nav_link>
              <.nav_link navigate={~p"/cves"} active={@active == :cves}>Vulnerabilities</.nav_link>
            </nav>
          </div>
          <div class="flex items-center gap-3">
            <.index_status status={@status} />
            <.theme_toggle />
          </div>
        </div>
        <nav class="site-container flex gap-1 pb-2 sm:hidden">
          <.nav_link navigate={~p"/"} active={@active == :dashboard}>Dashboard</.nav_link>
          <.nav_link navigate={~p"/cves"} active={@active == :cves}>Vulnerabilities</.nav_link>
        </nav>
      </header>

      <main class="site-container flex-1 py-8">
        {render_slot(@inner_block)}
      </main>

      <footer class="border-t border-base-300">
        <div class="site-container flex flex-wrap items-center justify-between gap-2 py-5 text-xs text-base-content/55">
          <span>
            vulsweb v{Application.spec(:vulsweb, :vsn)} · a web UI for
            <a href="https://github.com/future-architect/vuls" class="link link-hover">vuls</a>
            results
          </span>
          <span :if={@status && @status[:dir]} class="font-mono">{@status[:dir]}</span>
        </div>
      </footer>
    </div>

    <.flash_group flash={@flash} />
    """
  end

  attr :navigate, :string, required: true
  attr :active, :boolean, default: false
  slot :inner_block, required: true

  defp nav_link(assigns) do
    ~H"""
    <.link
      navigate={@navigate}
      class={[
        "btn btn-ghost btn-sm font-medium",
        @active && "bg-base-200 text-primary"
      ]}
    >
      {render_slot(@inner_block)}
    </.link>
    """
  end

  attr :status, :map, default: nil

  defp index_status(assigns) do
    ~H"""
    <div
      :if={@status}
      class="hidden items-center gap-2 text-xs text-base-content/60 md:flex"
      title={status_title(@status)}
    >
      <span class="relative flex size-2">
        <span
          :if={@status[:state] == :ready}
          class="absolute inline-flex size-full animate-ping rounded-full bg-success opacity-50"
        />
        <span class={[
          "relative inline-flex size-2 rounded-full",
          case @status[:state] do
            :ready -> "bg-success"
            :error -> "bg-error"
            _ -> "bg-warning"
          end
        ]} />
      </span>
      <span>
        {case @status[:state] do
          :ready -> "Live · #{@status[:files]} results"
          :error -> "Results unavailable"
          _ -> "Indexing…"
        end}
      </span>
    </div>
    """
  end

  defp status_title(%{state: :error, error: error, dir: dir}), do: "#{dir}: #{error}"

  defp status_title(%{refreshed_at: %DateTime{} = at, dir: dir}),
    do: "#{dir} · checked #{VulswebWeb.Format.ago(at)}"

  defp status_title(_), do: nil

  @doc """
  Shows the flash group with standard titles and content.
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title="We can't find the internet"
        phx-disconnected={
          show(".phx-client-error #client-error")
          |> JS.remove_attribute("hidden", to: ".phx-client-error #client-error")
        }
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        Attempting to reconnect
        <.icon name="lucide-refresh-cw" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title="Something went wrong!"
        phx-disconnected={
          show(".phx-server-error #server-error")
          |> JS.remove_attribute("hidden", to: ".phx-server-error #server-error")
        }
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        Attempting to reconnect
        <.icon name="lucide-refresh-cw" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end

  @doc """
  System / light (mudrock) / dark (mudrock-dark) theme toggle.
  See <head> in root.html.heex which applies the theme before page load.
  """
  def theme_toggle(assigns) do
    ~H"""
    <div class="relative flex flex-row items-center rounded-full border border-base-300 bg-base-200">
      <div class="absolute h-full w-1/3 rounded-full border border-base-300 bg-base-100 left-0 [[data-theme=mudrock]_&]:left-1/3 [[data-theme=mudrock-dark]_&]:left-2/3 [[data-theme-source=system]_&]:!left-0 transition-[left]" />

      <button
        class="relative flex w-1/3 cursor-pointer p-2"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="system"
        aria-label="Use system theme"
      >
        <.icon name="lucide-monitor" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="relative flex w-1/3 cursor-pointer p-2"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="mudrock"
        aria-label="Use light theme"
      >
        <.icon name="lucide-sun" class="size-4 opacity-75 hover:opacity-100" />
      </button>

      <button
        class="relative flex w-1/3 cursor-pointer p-2"
        phx-click={JS.dispatch("phx:set-theme")}
        data-phx-theme="mudrock-dark"
        aria-label="Use dark theme"
      >
        <.icon name="lucide-moon" class="size-4 opacity-75 hover:opacity-100" />
      </button>
    </div>
    """
  end
end
