defmodule VulswebWeb.CveIndexLive do
  use VulswebWeb, :live_view

  alias Vulsweb.Results
  alias Vulsweb.Results.Filter

  @per_page 100

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket), do: Results.subscribe()
    {:ok, socket |> assign(page_title: "Vulnerabilities") |> load()}
  end

  @impl true
  def handle_params(params, _uri, socket) do
    {:noreply, socket |> assign(filters: Filter.normalize(params)) |> apply_filters()}
  end

  @impl true
  def handle_event("filter", form, socket) do
    params = merge_filter(socket.assigns.filters, form)
    {:noreply, push_patch(socket, to: ~p"/cves" <> query(params), replace: true)}
  end

  @impl true
  def handle_info({:results_updated, _}, socket) do
    {:noreply, socket |> load() |> apply_filters()}
  end

  defp load(socket) do
    cves = Results.cves()

    assign(socket,
      all: cves,
      counts: Enum.frequencies_by(cves, & &1.severity),
      host_count: length(Results.hosts()),
      status: Results.status()
    )
  end

  defp apply_filters(socket) do
    filtered = Filter.cves(socket.assigns.all, socket.assigns.filters)
    {rows, page, pages} = Filter.paginate(filtered, socket.assigns.filters["page"], @per_page)
    assign(socket, rows: rows, page: page, pages: pages, filtered: length(filtered))
  end

  defp params(assigns), do: Map.put(assigns.filters, "page", assigns.page)

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active={:cves} status={@status}>
      <div class="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 class="text-2xl font-semibold tracking-tight">Vulnerabilities</h1>
          <p class="mt-1 text-sm text-base-content/60">
            Every CVE found in the latest scan of your {@host_count} hosts, worst first.
          </p>
        </div>
      </div>

      <div class="mt-6">
        <.filter_bar
          id="cve-filters"
          params={@filters}
          path={~p"/cves"}
          counts={@counts}
          shown={@filtered}
          total={length(@all)}
          placeholder="Search CVE, package, host, text"
          fix_label="Fix"
        >
          <:actions>
            <.link
              href={~p"/export/cves.csv" <> query(Map.drop(@filters, ["page"]))}
              class="btn btn-sm gap-1.5"
            >
              <.icon name="lucide-download" class="size-4" /> CSV
            </.link>
          </:actions>
        </.filter_bar>
      </div>

      <div class="mt-4 overflow-x-auto rounded-box border border-base-300 bg-base-100">
        <table class="table table-sm" id="cves-table">
          <thead>
            <tr class="text-xs uppercase tracking-wider text-base-content/55">
              <.sort_header
                field="cve"
                sort={@filters["sort"]}
                dir={@filters["dir"]}
                params={params(assigns)}
                path={~p"/cves"}
              >
                CVE
              </.sort_header>
              <.sort_header
                field="score"
                sort={@filters["sort"]}
                dir={@filters["dir"]}
                params={params(assigns)}
                path={~p"/cves"}
              >
                Severity
              </.sort_header>
              <.sort_header
                field="hosts"
                sort={@filters["sort"]}
                dir={@filters["dir"]}
                params={params(assigns)}
                path={~p"/cves"}
              >
                Hosts
              </.sort_header>
              <th>Packages</th>
              <th class="hidden xl:table-cell">Summary</th>
              <.sort_header
                field="published"
                sort={@filters["sort"]}
                dir={@filters["dir"]}
                params={params(assigns)}
                path={~p"/cves"}
                class="hidden lg:table-cell"
              >
                Published
              </.sort_header>
            </tr>
          </thead>
          <tbody>
            <tr
              :for={c <- @rows}
              id={"cve-#{c.cve_id}"}
              class="cursor-pointer align-top hover:bg-base-200/60"
              phx-click={JS.navigate(~p"/cves/#{c.cve_id}")}
            >
              <td class="whitespace-nowrap">
                <.link
                  navigate={~p"/cves/#{c.cve_id}"}
                  class="font-mono text-[0.8rem] font-semibold hover:text-primary"
                >
                  {c.cve_id}
                </.link>
                <div class="mt-1"><.threat_tags kev={c.kev} exploits={c.exploits} /></div>
              </td>
              <td class="whitespace-nowrap">
                <.severity_badge severity={c.severity} score={c.score} />
                <div :if={c.attack_vector} class="mt-1 text-[0.7rem] text-base-content/50">
                  {Vulsweb.Vuls.Scoring.attack_vector_label(c.attack_vector)}
                </div>
              </td>
              <td class="min-w-40">
                <div class="font-mono text-sm font-semibold tabular-nums">
                  {length(c.hosts)}
                  <span class="font-sans text-xs font-normal text-success">
                    <span :if={c.fixable_hosts > 0}>· {c.fixable_hosts} fixable</span>
                  </span>
                </div>
                <div class="mt-0.5 line-clamp-2 text-xs text-base-content/55">
                  {Enum.join(c.hosts, ", ")}
                </div>
              </td>
              <td class="max-w-56">
                <div class="line-clamp-2 text-xs">{Enum.join(c.packages, ", ")}</div>
              </td>
              <td class="hidden max-w-xl xl:table-cell">
                <p class="line-clamp-2 text-xs text-base-content/70">{c.summary}</p>
              </td>
              <td class="hidden whitespace-nowrap font-mono text-xs text-base-content/60 lg:table-cell">
                {Format.date(c.published)}
              </td>
            </tr>
            <tr :if={@rows == []}>
              <td colspan="6" class="py-10 text-center text-base-content/55">
                {if @all == [], do: "No vulnerabilities detected.", else: "No CVEs match the filters."}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <.pager page={@page} pages={@pages} total={@filtered} params={params(assigns)} path={~p"/cves"} />
    </Layouts.app>
    """
  end
end
