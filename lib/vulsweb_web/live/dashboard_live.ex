defmodule VulswebWeb.DashboardLive do
  use VulswebWeb, :live_view

  alias Vulsweb.Results

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Results.subscribe()

    {:ok,
     socket
     |> assign(page_title: "Dashboard", q: "", sort: "risk")
     |> load()}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    sort = if params["sort"] in ~w(name risk scanned), do: params["sort"], else: "risk"
    {:noreply, socket |> assign(q: params["q"] || "", sort: sort) |> filter_hosts()}
  end

  @impl true
  def handle_event("search", %{"q" => q}, socket) do
    {:noreply, push_patch(socket, to: ~p"/?#{params(q, socket.assigns.sort)}", replace: true)}
  end

  def handle_event("refresh", _params, socket) do
    Results.refresh()
    {:noreply, socket |> load() |> put_flash(:info, "Results directory re-scanned")}
  end

  @impl true
  def handle_info({:results_updated, _hosts}, socket), do: {:noreply, load(socket)}

  defp load(socket) do
    hosts = Results.hosts()
    cves = Results.cves()

    socket
    |> assign(
      status: Results.status(),
      all_hosts: hosts,
      totals: Vulsweb.Results.Aggregate.totals(hosts, cves),
      top_cves:
        cves |> Enum.sort_by(&{&1.kev, &1.exploits > 0, &1.score || 0}, :desc) |> Enum.take(8)
    )
    |> filter_hosts()
  end

  defp filter_hosts(socket) do
    q = socket.assigns.q |> String.downcase() |> String.trim()

    hosts =
      socket.assigns.all_hosts
      |> Enum.filter(fn h ->
        q == "" or
          Enum.any?(
            [h.host, h.family, h.release, h.kernel_release | h.ipv4],
            &(is_binary(&1) and String.contains?(String.downcase(&1), q))
          )
      end)
      |> Enum.sort_by(
        case socket.assigns.sort do
          "name" -> & &1.host
          "scanned" -> &(-Vulsweb.Vuls.Scan.sort_time(&1))
          _ -> &{-&1.counts.critical, -&1.counts.high, -&1.counts.total, &1.host}
        end
      )

    assign(socket, hosts: hosts)
  end

  defp params(q, sort) do
    %{q: q, sort: sort}
    |> Enum.reject(fn {k, v} -> v in ["", nil] or (k == :sort and v == "risk") end)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active={:dashboard} status={@status}>
      <div class="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 class="text-2xl font-semibold tracking-tight">Fleet overview</h1>
          <p class="mt-1 text-sm text-base-content/60">
            Latest vuls scan of every host. Updates live as new results arrive.
          </p>
        </div>
        <button id="refresh-btn" phx-click="refresh" class="btn btn-sm btn-ghost gap-1.5">
          <.icon name="lucide-refresh-cw" class="size-4 phx-click-loading:animate-spin" /> Rescan now
        </button>
      </div>

      <div
        :if={@status[:state] == :error}
        class="mt-6 rounded-box border border-error/30 bg-error/5 p-4 text-sm"
      >
        <div class="flex items-center gap-2 font-semibold text-error">
          <.icon name="lucide-triangle-alert" class="size-5" /> Cannot read results directory
        </div>
        <p class="mt-1 text-base-content/70">
          <span class="font-mono">{@status[:dir]}</span>: {@status[:error]}.
          Point <code class="font-mono">VULS_RESULTS_DIR</code>
          at the <code class="font-mono">results</code>
          directory of your vuls server.
        </p>
      </div>

      <%= if @all_hosts == [] do %>
        <div class="mt-8">
          <.empty
            icon="lucide-server"
            title={
              if @status[:state] == :indexing, do: "Indexing results…", else: "No scan results yet"
            }
          >
            Results posted to <code class="font-mono">vuls server -to-localfile</code>
            appear here automatically.
          </.empty>
        </div>
      <% else %>
        <section class="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
          <.stat label="Hosts" value={@totals.hosts} icon="lucide-server" />
          <.stat
            label="Unique CVEs"
            value={@totals.cves}
            icon="lucide-bug"
            hint={"#{Format.number(@totals.findings)} findings"}
            navigate={~p"/cves"}
          />
          <.stat
            label="Critical"
            value={@totals.critical}
            tone="text-sev-critical"
            icon="lucide-flame"
            navigate={~p"/cves?sev=critical"}
          />
          <.stat
            label="High"
            value={@totals.high}
            tone="text-sev-high"
            icon="lucide-triangle-alert"
            navigate={~p"/cves?sev=high"}
          />
          <.stat
            label="Known exploited"
            value={@totals.kev}
            tone="text-error"
            icon="lucide-shield-alert"
            navigate={~p"/cves?kev=1"}
          />
          <.stat
            label="Public exploits"
            value={@totals.exploitable}
            tone="text-warning"
            icon="lucide-zap"
            navigate={~p"/cves?exploit=1"}
          />
          <.stat
            label="Fixable"
            value={@totals.fixable}
            tone="text-success"
            icon="lucide-circle-arrow-up"
            hint="CVEs with an update available"
            navigate={~p"/cves?fix=fixable"}
          />
        </section>

        <section class="mt-3 rounded-box border border-base-300 bg-base-100 p-4">
          <div class="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm">
            <span class="font-medium">Unique CVEs by severity</span>
            <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-base-content/65">
              <span
                :for={sev <- [:critical, :high, :medium, :low, :unknown]}
                class="inline-flex items-center gap-1.5"
              >
                <span class={["size-2.5 rounded-sm", sev_bg(sev)]} />
                {Format.severity_label(sev)}
                <span class="font-mono tabular-nums text-base-content">
                  {Map.get(@totals, sev)}
                </span>
              </span>
            </div>
          </div>
          <.severity_bar counts={@totals} class="h-3" />
        </section>

        <div class="mt-8 grid gap-8 2xl:grid-cols-[1fr_26rem]">
          <section>
            <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
              <h2 class="text-lg font-semibold tracking-tight">
                Hosts <span class="text-base-content/45 font-normal">({length(@hosts)})</span>
              </h2>
              <div class="flex items-center gap-2">
                <form id="host-search" phx-change="search" phx-submit="search">
                  <label class="input input-sm w-56">
                    <.icon name="lucide-search" class="size-4 opacity-50" />
                    <input
                      type="search"
                      name="q"
                      value={@q}
                      placeholder="Filter hosts"
                      phx-debounce="200"
                      data-search-input
                      autocomplete="off"
                    />
                  </label>
                </form>
                <div class="join">
                  <.link
                    :for={{key, label} <- [{"risk", "Risk"}, {"name", "Name"}, {"scanned", "Recent"}]}
                    patch={~p"/?#{params(@q, key)}"}
                    class={["btn join-item btn-sm", @sort == key && "btn-active"]}
                  >
                    {label}
                  </.link>
                </div>
              </div>
            </div>

            <div class="overflow-x-auto rounded-box border border-base-300 bg-base-100">
              <table class="table table-sm" id="hosts-table">
                <thead>
                  <tr class="text-xs uppercase tracking-wider text-base-content/55">
                    <th>Host</th>
                    <th>OS</th>
                    <th>Last scan</th>
                    <th>Severity</th>
                    <th class="text-right">CVEs</th>
                    <th class="text-right">Fixable</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    :for={h <- @hosts}
                    id={"host-#{h.host}"}
                    class="group cursor-pointer hover:bg-base-200/60"
                    phx-click={JS.navigate(~p"/hosts/#{h.host}")}
                  >
                    <td>
                      <.link
                        navigate={~p"/hosts/#{h.host}"}
                        class="font-medium group-hover:text-primary"
                      >
                        {h.host}
                      </.link>
                      <div :if={h.ipv4 != []} class="font-mono text-xs text-base-content/50">
                        {Enum.join(h.ipv4, ", ")}
                      </div>
                    </td>
                    <td class="whitespace-nowrap">
                      <div>{Vulsweb.Vuls.Scan.os_label(h) || "—"}</div>
                      <div
                        :if={h.kernel_release}
                        class="max-w-48 truncate font-mono text-xs text-base-content/50"
                      >
                        {h.kernel_release}
                      </div>
                    </td>
                    <td class="whitespace-nowrap">
                      <.time_ago at={h.scanned_at} id={"scanned-#{h.host}"} />
                      <span
                        :if={Format.stale?(h.scanned_at)}
                        class="ml-1 rounded bg-warning/15 px-1.5 py-px text-[0.68rem] font-semibold text-warning"
                      >
                        STALE
                      </span>
                    </td>
                    <td><.severity_counts counts={h.counts} /></td>
                    <td class="text-right font-mono tabular-nums">{h.counts.total}</td>
                    <td class="text-right font-mono tabular-nums text-success">
                      {h.counts.fixable}
                    </td>
                    <td class="whitespace-nowrap text-right">
                      <span class="inline-flex items-center gap-1.5">
                        <.threat_tags kev={h.counts.kev > 0} exploits={h.counts.exploitable} />
                        <span :if={h.reboot_required} title="Reboot required" class="text-warning">
                          <.icon name="lucide-rotate-cw" class="size-4" />
                        </span>
                        <span
                          :if={h.errors != [] or h.parse_error}
                          title={h.parse_error || Enum.join(h.errors, "\n")}
                          class="text-error"
                        >
                          <.icon name="lucide-circle-alert" class="size-4" />
                        </span>
                        <span
                          :if={h.warnings != []}
                          title={Enum.join(h.warnings, "\n")}
                          class="text-warning"
                        >
                          <.icon name="lucide-triangle-alert" class="size-4" />
                        </span>
                      </span>
                    </td>
                  </tr>
                  <tr :if={@hosts == []}>
                    <td colspan="7" class="py-8 text-center text-base-content/55">
                      No hosts match “{@q}”.
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section>
            <div class="mb-3 flex items-center justify-between">
              <h2 class="text-lg font-semibold tracking-tight">Act on these first</h2>
              <.link navigate={~p"/cves"} class="link link-hover text-sm text-primary">
                All CVEs →
              </.link>
            </div>
            <ul class="divide-y divide-base-300 overflow-hidden rounded-box border border-base-300 bg-base-100">
              <li :for={c <- @top_cves} id={"top-#{c.cve_id}"}>
                <.link
                  navigate={~p"/cves/#{c.cve_id}"}
                  class="block px-4 py-3 transition hover:bg-base-200/60"
                >
                  <div class="flex items-center justify-between gap-2">
                    <span class="font-mono text-sm font-semibold">{c.cve_id}</span>
                    <.severity_badge severity={c.severity} score={c.score} />
                  </div>
                  <p class="mt-1 line-clamp-2 text-xs text-base-content/65">{c.summary}</p>
                  <div class="mt-2 flex items-center justify-between gap-2 text-xs text-base-content/55">
                    <span>
                      {length(c.hosts)} {if length(c.hosts) == 1, do: "host", else: "hosts"} · {Enum.take(
                        c.packages,
                        2
                      )
                      |> Enum.join(", ")}
                    </span>
                    <.threat_tags kev={c.kev} exploits={c.exploits} />
                  </div>
                </.link>
              </li>
              <li :if={@top_cves == []} class="px-4 py-8 text-center text-sm text-base-content/55">
                Nothing detected. Nice.
              </li>
            </ul>
          </section>
        </div>
      <% end %>
    </Layouts.app>
    """
  end
end
