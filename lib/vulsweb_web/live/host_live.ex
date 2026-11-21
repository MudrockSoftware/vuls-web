defmodule VulswebWeb.HostLive do
  use VulswebWeb, :live_view

  alias Vulsweb.Results
  alias Vulsweb.Results.Filter
  alias Vulsweb.Vuls.Scan

  @per_page 100
  @tabs ~w(vulns packages history info)

  @impl true
  def mount(%{"host" => host}, _session, socket) do
    if connected?(socket), do: Results.subscribe()
    {:ok, assign(socket, host: host, page_title: host, scan_id: nil, scan: nil, diff: nil)}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    tab = if params["tab"] in @tabs, do: params["tab"], else: "vulns"

    socket =
      socket
      |> assign(
        tab: tab,
        raw_params: params,
        filters: Filter.normalize(params),
        pkg_params: %{
          "q" => params["pq"] || "",
          "upgradable" => params["upgradable"] || "",
          "vulnerable" => params["vulnerable"] || ""
        },
        status: Results.status()
      )
      |> load_scan(params["scan"])
      |> apply_filters()

    {:noreply, socket}
  end

  @impl true
  def handle_event("filter", form, socket) do
    params = merge_filter(base_params(socket), form)
    {:noreply, push_patch(socket, to: self_path(socket, params), replace: true)}
  end

  def handle_event("pkg_filter", form, socket) do
    params =
      base_params(socket)
      |> Map.merge(%{
        "pq" => form["pq"],
        "upgradable" => form["upgradable"],
        "vulnerable" => form["vulnerable"],
        "page" => nil
      })

    {:noreply, push_patch(socket, to: self_path(socket, params), replace: true)}
  end

  @impl true
  def handle_info({:results_updated, hosts}, socket) do
    if socket.assigns.host in hosts do
      # Following the latest scan: reload it. Pinned to an older scan: keep it.
      reload_id = if socket.assigns.raw_params["scan"], do: socket.assigns.scan_id, else: nil

      {:noreply,
       socket
       |> assign(scan_id: nil, status: Results.status())
       |> load_scan(reload_id)
       |> apply_filters()}
    else
      {:noreply, assign(socket, status: Results.status())}
    end
  end

  defp load_scan(%{assigns: %{scan_id: id}} = socket, id) when not is_nil(id), do: socket

  defp load_scan(socket, requested) do
    host = socket.assigns.host
    latest = Results.host(host)

    scan =
      case requested do
        nil ->
          latest

        id ->
          case Results.scan(host, id) do
            {:ok, scan} -> scan
            _ -> latest
          end
      end

    if scan do
      assign(socket,
        scan: scan,
        scan_id: if(requested, do: scan.id, else: nil),
        latest_id: latest && latest.id,
        history: Results.history(host),
        diff: Results.diff(scan)
      )
    else
      assign(socket, scan: nil, scan_id: nil, latest_id: nil, history: [], diff: nil)
    end
  end

  defp apply_filters(%{assigns: %{scan: nil}} = socket),
    do: assign(socket, rows: [], page: 1, pages: 1, filtered: 0, packages: [])

  defp apply_filters(socket) do
    %{scan: scan, filters: filters} = socket.assigns
    filtered = Filter.vulns(scan.vulns, filters)
    {rows, page, pages} = Filter.paginate(filtered, filters["page"], @per_page)
    packages = Filter.packages(scan.packages || [], socket.assigns.pkg_params)

    assign(socket,
      rows: rows,
      page: page,
      pages: pages,
      filtered: length(filtered),
      packages: packages
    )
  end

  defp base_params(socket) do
    Map.take(
      socket.assigns.raw_params,
      ~w(scan tab q sev fix kev exploit sort dir pq upgradable vulnerable)
    )
  end

  defp self_path(socket, params), do: ~p"/hosts/#{socket.assigns.host}" <> query(params)

  defp tab_path(host, params, tab) do
    ~p"/hosts/#{host}" <>
      query(
        params
        |> Map.take(["scan"])
        |> Map.put("tab", if(tab == "vulns", do: nil, else: tab))
      )
  end

  defp scan_path(host, latest_id, id) do
    ~p"/hosts/#{host}" <> query(%{"scan" => if(id == latest_id, do: nil, else: id)})
  end

  defp filter_params(assigns) do
    assigns.filters
    |> Map.merge(Map.take(assigns.raw_params, ["scan"]))
    |> Map.put("page", assigns.page)
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active={:dashboard} status={@status}>
      <nav class="mb-4 text-sm text-base-content/60">
        <.link navigate={~p"/"} class="link link-hover">Dashboard</.link>
        <span class="mx-1.5">/</span>
        <span class="text-base-content">{@host}</span>
      </nav>

      <%= if @scan == nil do %>
        <.empty icon="lucide-server-off" title="Host not found">
          No results for <span class="font-mono">{@host}</span> in the results directory (yet).
        </.empty>
      <% else %>
        <.host_header
          scan={@scan}
          history={@history}
          latest_id={@latest_id}
          host={@host}
          diff={@diff}
        />

        <div role="tablist" class="tabs tabs-border mt-6">
          <.link
            :for={
              {key, label, count} <- [
                {"vulns", "Vulnerabilities", @scan.counts.total},
                {"packages", "Packages", @scan.packages_count},
                {"history", "History", length(@history)},
                {"info", "Scan info", length(@scan.errors) + length(@scan.warnings)}
              ]
            }
            role="tab"
            patch={tab_path(@host, @raw_params, key)}
            class={["tab gap-2", @tab == key && "tab-active font-medium"]}
          >
            {label}
            <span class="badge badge-sm badge-ghost font-mono">{count}</span>
          </.link>
        </div>

        <div class="mt-5">
          <%= case @tab do %>
            <% "vulns" -> %>
              <.vulns_tab {assigns} />
            <% "packages" -> %>
              <.packages_tab {assigns} />
            <% "history" -> %>
              <.history_tab {assigns} />
            <% "info" -> %>
              <.info_tab scan={@scan} />
          <% end %>
        </div>
      <% end %>
    </Layouts.app>
    """
  end

  attr :scan, Scan, required: true
  attr :history, :list, required: true
  attr :latest_id, :string, required: true
  attr :host, :string, required: true
  attr :diff, :map, default: nil

  defp host_header(assigns) do
    ~H"""
    <div class="grid gap-4 lg:grid-cols-[1fr_auto]">
      <div>
        <div class="flex flex-wrap items-center gap-3">
          <h1 class="text-2xl font-semibold tracking-tight">{@host}</h1>
          <span
            :if={@scan.reboot_required}
            class="inline-flex items-center gap-1 rounded-md bg-warning/15 px-2 py-0.5 text-xs font-semibold text-warning"
          >
            <.icon name="lucide-rotate-cw" class="size-4" /> Reboot required
          </span>
          <span
            :if={@scan.id != @latest_id}
            class="inline-flex items-center gap-1 rounded-md bg-info/15 px-2 py-0.5 text-xs font-semibold text-info"
          >
            <.icon name="lucide-clock" class="size-4" /> Viewing an older scan
          </span>
          <span
            :if={@scan.id == @latest_id and Format.stale?(@scan.scanned_at)}
            class="rounded-md bg-warning/15 px-2 py-0.5 text-xs font-semibold text-warning"
          >
            STALE
          </span>
        </div>
        <dl class="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-sm">
          <div>
            <dt class="text-xs text-base-content/50">OS</dt>
            <dd>{Scan.os_label(@scan) || "—"}</dd>
          </div>
          <div :if={@scan.kernel_release}>
            <dt class="text-xs text-base-content/50">Kernel</dt>
            <dd class="font-mono text-[0.8rem]">{@scan.kernel_release}</dd>
          </div>
          <div :if={@scan.container}>
            <dt class="text-xs text-base-content/50">Container</dt>
            <dd>{@scan.container} on {@scan.server_name}</dd>
          </div>
          <div :if={@scan.ipv4 != []}>
            <dt class="text-xs text-base-content/50">IPv4</dt>
            <dd class="font-mono text-[0.8rem]">{Enum.join(@scan.ipv4, ", ")}</dd>
          </div>
          <div>
            <dt class="text-xs text-base-content/50">Scanned</dt>
            <dd><.local_time at={@scan.scanned_at} id="scanned-at" /></dd>
          </div>
          <div>
            <dt class="text-xs text-base-content/50">Packages</dt>
            <dd>
              {Format.number(@scan.packages_count)}
              <span :if={@scan.upgradable_count > 0} class="text-base-content/55">
                ({@scan.upgradable_count} upgradable)
              </span>
            </dd>
          </div>
        </dl>
      </div>

      <div class="flex items-start gap-2">
        <div :if={length(@history) > 1} class="dropdown dropdown-end">
          <div tabindex="0" role="button" class="btn btn-sm gap-1.5">
            <.icon name="lucide-clock" class="size-4" />
            {if @scan.id == @latest_id, do: "Latest scan", else: Format.datetime(@scan.scanned_at)}
            <.icon name="lucide-chevron-down" class="size-4" />
          </div>
          <ul
            tabindex="0"
            class="dropdown-content menu z-50 mt-2 max-h-80 w-72 flex-nowrap overflow-y-auto rounded-box border border-base-300 bg-base-100 p-1 shadow-lg"
          >
            <li :for={s <- @history}>
              <.link
                patch={scan_path(@host, @latest_id, s.id)}
                class={["justify-between", s.id == @scan.id && "menu-active"]}
              >
                <span class="font-mono text-xs">{Format.datetime(s.scanned_at)}</span>
                <span class="font-mono text-xs opacity-70">{s.counts.total} CVEs</span>
              </.link>
            </li>
          </ul>
        </div>
        <.link
          href={~p"/hosts/#{@host}/export.csv" <> query(%{"scan" => if(@scan.id != @latest_id, do: @scan.id)})}
          class="btn btn-sm gap-1.5"
        >
          <.icon name="lucide-download" class="size-4" /> CSV
        </.link>
      </div>
    </div>

    <div class="mt-5 grid gap-3 md:grid-cols-[1fr_auto]">
      <div class="rounded-box border border-base-300 bg-base-100 p-4">
        <div class="mb-3 flex flex-wrap items-center justify-between gap-2 text-sm">
          <span class="font-medium">{@scan.counts.total} CVEs</span>
          <.severity_counts counts={@scan.counts} />
        </div>
        <.severity_bar counts={@scan.counts} class="h-2.5" />
        <div class="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-base-content/65">
          <span>
            <span class="font-mono font-semibold text-success">{@scan.counts.fixable}</span>
            with a fix available
          </span>
          <span>
            <span class="font-mono font-semibold">{@scan.counts.unfixed}</span> not fixed upstream
          </span>
          <span :if={@scan.counts.kev > 0}>
            <span class="font-mono font-semibold text-error">{@scan.counts.kev}</span> known exploited
          </span>
          <span :if={@scan.counts.exploitable > 0}>
            <span class="font-mono font-semibold text-warning">{@scan.counts.exploitable}</span>
            with public exploits
          </span>
        </div>
      </div>
      <div
        :if={@diff}
        class="min-w-64 rounded-box border border-base-300 bg-base-100 p-4 text-sm"
        id="scan-diff"
      >
        <div class="text-xs text-base-content/55">
          Since previous scan ({Format.ago(@diff.previous.scanned_at)})
        </div>
        <div class="mt-2 flex items-center gap-5">
          <span class="text-2xl font-semibold tabular-nums text-error">+{length(@diff.added)}</span>
          <span class="text-2xl font-semibold tabular-nums text-success">
            −{length(@diff.resolved)}
          </span>
        </div>
        <details :if={@diff.added != [] or @diff.resolved != []} class="mt-2">
          <summary class="cursor-pointer text-xs text-primary">Show changes</summary>
          <ul class="mt-2 max-h-52 space-y-1 overflow-y-auto text-xs">
            <li :for={v <- @diff.added} class="flex items-center justify-between gap-2">
              <.link navigate={~p"/cves/#{v.cve_id}"} class="font-mono text-error hover:underline">
                + {v.cve_id}
              </.link>
              <.severity_badge severity={v.severity} />
            </li>
            <li :for={v <- @diff.resolved} class="flex items-center justify-between gap-2">
              <.link
                navigate={~p"/cves/#{v.cve_id}"}
                class="font-mono text-success hover:underline"
              >
                − {v.cve_id}
              </.link>
              <.severity_badge severity={v.severity} />
            </li>
          </ul>
        </details>
      </div>
    </div>
    """
  end

  defp vulns_tab(assigns) do
    ~H"""
    <.filter_bar
      id="vuln-filters"
      params={@filters}
      path={~p"/hosts/#{@host}"}
      counts={@scan.counts}
      shown={@filtered}
      total={@scan.counts.total}
    />

    <div class="mt-4 overflow-x-auto rounded-box border border-base-300 bg-base-100">
      <table class="table table-sm" id="vulns-table">
        <thead>
          <tr class="text-xs uppercase tracking-wider text-base-content/55">
            <.sort_header
              field="cve"
              sort={@filters["sort"]}
              dir={@filters["dir"]}
              params={filter_params(assigns)}
              path={~p"/hosts/#{@host}"}
            >
              CVE
            </.sort_header>
            <.sort_header
              field="score"
              sort={@filters["sort"]}
              dir={@filters["dir"]}
              params={filter_params(assigns)}
              path={~p"/hosts/#{@host}"}
            >
              Severity
            </.sort_header>
            <.sort_header
              field="package"
              sort={@filters["sort"]}
              dir={@filters["dir"]}
              params={filter_params(assigns)}
              path={~p"/hosts/#{@host}"}
            >
              Affected
            </.sort_header>
            <.sort_header
              field="fix"
              sort={@filters["sort"]}
              dir={@filters["dir"]}
              params={filter_params(assigns)}
              path={~p"/hosts/#{@host}"}
            >
              Fix
            </.sort_header>
            <th class="hidden xl:table-cell">Summary</th>
            <.sort_header
              field="published"
              sort={@filters["sort"]}
              dir={@filters["dir"]}
              params={filter_params(assigns)}
              path={~p"/hosts/#{@host}"}
              class="hidden lg:table-cell"
            >
              Published
            </.sort_header>
          </tr>
        </thead>
        <tbody>
          <tr :for={v <- @rows} id={"vuln-#{v.cve_id}"} class="align-top hover:bg-base-200/60">
            <td class="whitespace-nowrap">
              <.link
                navigate={~p"/cves/#{v.cve_id}"}
                class="font-mono text-[0.8rem] font-semibold hover:text-primary"
              >
                {v.cve_id}
              </.link>
              <div class="mt-1">
                <.threat_tags kev={v.kev} exploits={v.exploits + v.metasploits} />
              </div>
            </td>
            <td class="whitespace-nowrap">
              <.severity_badge severity={v.severity} score={v.score} />
              <div :if={v.cvss_version} class="mt-1 text-[0.7rem] text-base-content/50">
                CVSS {v.cvss_version} · {Format.source_label(v.cvss_type)}
              </div>
            </td>
            <td class="min-w-48">
              <div :for={a <- Enum.take(v.affected, 4)} class="text-[0.8rem] leading-5">
                <span class="font-medium">{a.name}</span>
                <span :if={a.version} class="font-mono text-xs text-base-content/55">
                  {a.version}
                </span>
                <span :if={a.fixed_in || a.new_version} class="font-mono text-xs text-success">
                  → {a.fixed_in || a.new_version}
                </span>
              </div>
              <div :if={length(v.affected) > 4} class="text-xs text-base-content/50">
                +{length(v.affected) - 4} more
              </div>
            </td>
            <td class="whitespace-nowrap"><.fix_badge status={v.fix_status} /></td>
            <td class="hidden max-w-xl xl:table-cell">
              <p class="line-clamp-2 text-xs text-base-content/70">{v.summary}</p>
            </td>
            <td class="hidden whitespace-nowrap font-mono text-xs text-base-content/60 lg:table-cell">
              {Format.date(v.published)}
            </td>
          </tr>
          <tr :if={@rows == []}>
            <td colspan="6" class="py-10 text-center text-base-content/55">
              {if @scan.counts.total == 0,
                do: "No vulnerabilities detected in this scan.",
                else: "No CVEs match the current filters."}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <.pager
      page={@page}
      pages={@pages}
      total={@filtered}
      params={filter_params(assigns)}
      path={~p"/hosts/#{@host}"}
    />
    """
  end

  defp packages_tab(assigns) do
    ~H"""
    <form id="pkg-filters" phx-change="pkg_filter" class="flex flex-wrap items-center gap-2">
      <label class="input input-sm w-full sm:w-72">
        <.icon name="lucide-search" class="size-4 opacity-50" />
        <input
          type="search"
          name="pq"
          value={@pkg_params["q"]}
          placeholder="Filter packages"
          phx-debounce="200"
          data-search-input
          autocomplete="off"
        />
      </label>
      <label class="label cursor-pointer gap-1.5 rounded-field border border-base-300 px-2.5 py-1 text-sm">
        <input type="hidden" name="upgradable" value="" />
        <input
          type="checkbox"
          name="upgradable"
          value="1"
          checked={@pkg_params["upgradable"] == "1"}
          class="checkbox checkbox-xs"
        /> Upgradable
      </label>
      <label class="label cursor-pointer gap-1.5 rounded-field border border-base-300 px-2.5 py-1 text-sm">
        <input type="hidden" name="vulnerable" value="" />
        <input
          type="checkbox"
          name="vulnerable"
          value="1"
          checked={@pkg_params["vulnerable"] == "1"}
          class="checkbox checkbox-xs"
        /> Vulnerable
      </label>
      <span class="ml-auto text-xs text-base-content/55">
        {Format.number(length(@packages))} of {Format.number(@scan.packages_count)} packages
      </span>
    </form>

    <div
      :if={@scan.packages == nil or @scan.packages == []}
      class="mt-4 text-sm text-base-content/60"
    >
      <.empty icon="lucide-package" title="No package list">
        This scan does not include installed packages.
      </.empty>
    </div>

    <div
      :if={@scan.packages not in [nil, []]}
      class="mt-4 overflow-x-auto rounded-box border border-base-300 bg-base-100"
    >
      <table class="table table-sm" id="packages-table">
        <thead>
          <tr class="text-xs uppercase tracking-wider text-base-content/55">
            <th>Package</th>
            <th>Installed</th>
            <th>Candidate</th>
            <th>Arch</th>
            <th class="text-right">CVEs</th>
          </tr>
        </thead>
        <tbody>
          <tr :for={p <- Enum.take(@packages, 1000)} class="hover:bg-base-200/60">
            <td class="font-medium">{p.name}</td>
            <td class="font-mono text-xs">{p.version}</td>
            <td class="font-mono text-xs text-success">{p.new_version}</td>
            <td class="font-mono text-xs text-base-content/55">{p.arch}</td>
            <td class="text-right">
              <.link
                :if={p.vulns > 0}
                patch={~p"/hosts/#{@host}" <> query(%{"q" => p.name, "scan" => @raw_params["scan"]})}
                class="font-mono text-xs font-semibold text-error hover:underline"
              >
                {p.vulns}
              </.link>
            </td>
          </tr>
        </tbody>
      </table>
      <p :if={length(@packages) > 1000} class="p-3 text-xs text-base-content/55">
        Showing the first 1,000 packages, refine the filter to see more.
      </p>
    </div>
    """
  end

  defp history_tab(assigns) do
    max_total = assigns.history |> Enum.map(& &1.counts.total) |> Enum.max(fn -> 1 end) |> max(1)
    assigns = assign(assigns, :max_total, max_total)

    ~H"""
    <div class="overflow-x-auto rounded-box border border-base-300 bg-base-100">
      <table class="table table-sm" id="history-table">
        <thead>
          <tr class="text-xs uppercase tracking-wider text-base-content/55">
            <th>Scanned</th>
            <th>Severity</th>
            <th class="w-1/3">Trend</th>
            <th class="text-right">CVEs</th>
            <th class="text-right">Fixable</th>
            <th>File</th>
          </tr>
        </thead>
        <tbody>
          <tr
            :for={s <- @history}
            id={"scan-#{Format.dom_id(s.dir)}"}
            class={["hover:bg-base-200/60", s.id == @scan.id && "bg-primary/5"]}
          >
            <td class="whitespace-nowrap">
              <.link patch={scan_path(@host, @latest_id, s.id)} class="hover:text-primary">
                <.local_time at={s.scanned_at} id={"hist-#{Format.dom_id(s.dir)}"} />
              </.link>
              <span
                :if={s.id == @latest_id}
                class="ml-1 rounded bg-success/15 px-1.5 py-px text-[0.68rem] font-semibold text-success"
              >
                LATEST
              </span>
              <span
                :if={s.parse_error}
                class="ml-1 rounded bg-error/15 px-1.5 py-px text-[0.68rem] font-semibold text-error"
                title={s.parse_error}
              >
                UNREADABLE
              </span>
            </td>
            <td><.severity_counts counts={s.counts} /></td>
            <td>
              <div style={"width: #{max(s.counts.total / @max_total * 100, 2)}%"}>
                <.severity_bar counts={s.counts} class="h-2" />
              </div>
            </td>
            <td class="text-right font-mono tabular-nums">{s.counts.total}</td>
            <td class="text-right font-mono tabular-nums text-success">{s.counts.fixable}</td>
            <td class="font-mono text-xs text-base-content/50">
              {s.dir} · {Format.bytes(s.size)}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    """
  end

  attr :scan, Scan, required: true

  defp info_tab(assigns) do
    ~H"""
    <div class="grid gap-4 lg:grid-cols-2">
      <div class="rounded-box border border-base-300 bg-base-100 p-4">
        <h3 class="mb-3 font-semibold">Scan</h3>
        <dl class="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
          <dt class="text-base-content/55">Server name</dt>
          <dd>{@scan.server_name || "—"}</dd>
          <dt class="text-base-content/55">Scan mode</dt>
          <dd>{@scan.scan_mode || "—"}</dd>
          <dt class="text-base-content/55">Scanned via</dt>
          <dd>{@scan.scanned_via || "—"}</dd>
          <dt class="text-base-content/55">Scanned by</dt>
          <dd>{@scan.scanned_by || "—"}</dd>
          <dt class="text-base-content/55">Scanned at</dt>
          <dd><.local_time at={@scan.scanned_at} id="info-scanned" /></dd>
          <dt class="text-base-content/55">Reported at</dt>
          <dd><.local_time at={@scan.reported_at} id="info-reported" /></dd>
          <dt class="text-base-content/55">vuls version</dt>
          <dd class="font-mono text-xs">{@scan.scanned_version || "—"}</dd>
          <dt class="text-base-content/55">Platform</dt>
          <dd>{@scan.platform || "—"}</dd>
          <dt class="text-base-content/55">IPv6</dt>
          <dd class="font-mono text-xs">
            {Enum.join(@scan.ipv6, ", ") |> then(&if(&1 == "", do: "—", else: &1))}
          </dd>
          <dt class="text-base-content/55">Libraries</dt>
          <dd>{@scan.libraries_count}</dd>
          <dt class="text-base-content/55">Result file</dt>
          <dd class="break-all font-mono text-xs">{@scan.path} ({Format.bytes(@scan.size)})</dd>
        </dl>
      </div>
      <div class="space-y-4">
        <div
          :if={@scan.parse_error}
          class="rounded-box border border-error/30 bg-error/5 p-4 text-sm"
        >
          <h3 class="font-semibold text-error">Unreadable result file</h3>
          <p class="mt-1 font-mono text-xs">{@scan.parse_error}</p>
        </div>
        <div class="rounded-box border border-base-300 bg-base-100 p-4">
          <h3 class="mb-2 font-semibold">Errors</h3>
          <p :if={@scan.errors == []} class="text-sm text-base-content/55">None</p>
          <pre
            :for={e <- @scan.errors}
            class="mt-2 whitespace-pre-wrap rounded-field bg-error/5 p-2 font-mono text-xs text-error"
          >{e}</pre>
        </div>
        <div class="rounded-box border border-base-300 bg-base-100 p-4">
          <h3 class="mb-2 font-semibold">Warnings</h3>
          <p :if={@scan.warnings == []} class="text-sm text-base-content/55">None</p>
          <pre
            :for={w <- @scan.warnings}
            class="mt-2 whitespace-pre-wrap rounded-field bg-warning/5 p-2 font-mono text-xs text-warning"
          >{w}</pre>
        </div>
      </div>
    </div>
    """
  end
end
