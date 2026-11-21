defmodule VulswebWeb.CveLive do
  use VulswebWeb, :live_view

  alias Vulsweb.Results
  alias Vulsweb.Vuls.Scan

  @impl true
  def mount(%{"cve_id" => cve_id}, _session, socket) do
    if connected?(socket), do: Results.subscribe()
    {:ok, socket |> assign(cve_id: cve_id, page_title: cve_id) |> load()}
  end

  @impl true
  def handle_info({:results_updated, _}, socket), do: {:noreply, load(socket)}

  defp load(socket) do
    case Results.cve(socket.assigns.cve_id) do
      {:ok, %{row: row, detail: detail, hosts: hosts}} ->
        assign(socket, row: row, detail: detail, hosts: hosts, status: Results.status())

      {:error, :not_found} ->
        assign(socket, row: nil, detail: nil, hosts: [], status: Results.status())
    end
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} active={:cves} status={@status}>
      <nav class="mb-4 text-sm text-base-content/60">
        <.link navigate={~p"/cves"} class="link link-hover">Vulnerabilities</.link>
        <span class="mx-1.5">/</span>
        <span class="font-mono text-base-content">{@cve_id}</span>
      </nav>

      <%= if @row == nil do %>
        <.empty icon="lucide-shield-check" title="Not found in current results">
          <span class="font-mono">{@cve_id}</span>
          is not present in the latest scan of any host. It may have been fixed.
          <a href={Format.nvd_url(@cve_id)} class="link text-primary" target="_blank" rel="noopener">
            View on NVD
          </a>
        </.empty>
      <% else %>
        <div class="grid gap-6 xl:grid-cols-[1fr_22rem]">
          <div class="min-w-0 space-y-6">
            <.header_card row={@row} detail={@detail} cve_id={@cve_id} />
            <.hosts_card hosts={@hosts} />
            <.scores_card :if={@detail && @detail.scores != []} detail={@detail} />
            <.kev_card :if={@detail && @detail.kevs != []} kevs={@detail.kevs} />
            <.exploits_card
              :if={@detail && (@detail.exploits != [] or @detail.metasploits != [])}
              detail={@detail}
            />
            <.sources_card :if={@detail && @detail.contents != []} detail={@detail} />
          </div>
          <aside :if={@detail} class="space-y-6">
            <.facts_card detail={@detail} row={@row} />
            <.cwe_card :if={@detail.cwes != []} cwes={@detail.cwes} />
            <.advisories_card :if={@detail.advisories != []} advisories={@detail.advisories} />
            <.mitigations_card :if={@detail.mitigations != []} mitigations={@detail.mitigations} />
            <.references_card :if={@detail.references != []} references={@detail.references} />
          </aside>
        </div>
      <% end %>
    </Layouts.app>
    """
  end

  defp header_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100 p-5">
      <div class="flex flex-wrap items-center gap-3">
        <h1 class="font-mono text-2xl font-semibold tracking-tight">{@cve_id}</h1>
        <button
          id="copy-cve"
          phx-hook="CopyToClipboard"
          data-copy={@cve_id}
          class="btn btn-ghost btn-xs gap-1 data-[copied]:text-success"
          title="Copy CVE id"
        >
          <.icon name="lucide-copy" class="size-4" />
        </button>
        <.severity_badge severity={@row.severity} score={@row.score} class="text-sm" />
        <.threat_tags kev={@row.kev} exploits={@row.exploits} />
      </div>
      <p
        :if={@detail && @detail.title && @detail.title != @cve_id}
        class="mt-3 font-medium"
      >
        {@detail.title}
      </p>
      <p class="mt-3 whitespace-pre-line text-sm leading-relaxed text-base-content/80">
        {(@detail && @detail.summary) || @row.summary || "No description available."}
      </p>
      <div class="mt-4 flex flex-wrap gap-2 text-xs">
        <a
          href={Format.nvd_url(@cve_id)}
          target="_blank"
          rel="noopener"
          class="btn btn-xs gap-1"
        >
          NVD <.icon name="lucide-external-link" class="size-3.5" />
        </a>
        <a
          href={"https://www.cve.org/CVERecord?id=#{@cve_id}"}
          target="_blank"
          rel="noopener"
          class="btn btn-xs gap-1"
        >
          CVE.org <.icon name="lucide-external-link" class="size-3.5" />
        </a>
        <a
          :if={@row.kev}
          href={"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=#{@cve_id}"}
          target="_blank"
          rel="noopener"
          class="btn btn-xs gap-1"
        >
          CISA KEV <.icon name="lucide-external-link" class="size-3.5" />
        </a>
      </div>
    </section>
    """
  end

  defp hosts_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100">
      <h2 class="border-b border-base-300 px-5 py-3 font-semibold">
        Affected hosts <span class="font-normal text-base-content/50">({length(@hosts)})</span>
      </h2>
      <div class="overflow-x-auto">
        <table class="table table-sm" id="affected-hosts">
          <thead>
            <tr class="text-xs uppercase tracking-wider text-base-content/55">
              <th>Host</th>
              <th>Package</th>
              <th>Installed</th>
              <th>Fixed in</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <%= for {scan, vuln} <- @hosts do %>
              <tr
                :for={{a, i} <- Enum.with_index(non_empty(vuln.affected))}
                class="align-top hover:bg-base-200/60"
              >
                <td :if={i == 0} rowspan={max(length(vuln.affected), 1)} class="whitespace-nowrap">
                  <.link navigate={~p"/hosts/#{scan.host}"} class="font-medium hover:text-primary">
                    {scan.host}
                  </.link>
                  <div class="text-xs text-base-content/50">{Scan.os_label(scan)}</div>
                </td>
                <td class="text-[0.8rem]">
                  <span class="font-medium">{a && a.name}</span>
                  <span
                    :if={a && a.kind not in [:package]}
                    class="ml-1 rounded bg-base-200 px-1 text-[0.65rem] uppercase text-base-content/60"
                  >
                    {a.kind}
                  </span>
                  <div
                    :if={a && a.path}
                    class="break-all font-mono text-[0.7rem] text-base-content/50"
                  >
                    {a.path}
                  </div>
                </td>
                <td class="font-mono text-xs">{a && a.version}</td>
                <td class="font-mono text-xs text-success">
                  {a && (a.fixed_in || a.new_version)}
                </td>
                <td class="whitespace-nowrap">
                  <span :if={a && a.fix_state} class="text-xs text-base-content/60">
                    {a.fix_state}
                  </span>
                  <.fix_badge :if={!(a && a.fix_state)} status={package_status(a, vuln)} />
                </td>
              </tr>
            <% end %>
          </tbody>
        </table>
      </div>
    </section>
    """
  end

  # Per-package view of vuls' fix status; falls back to the host verdict.
  defp package_status(nil, vuln), do: vuln.fix_status
  defp package_status(%{not_fixed_yet: true}, _vuln), do: :unfixed
  defp package_status(%{fixed_in: f}, _vuln) when is_binary(f), do: :fixable
  defp package_status(%{new_version: n}, _vuln) when is_binary(n), do: :fixable
  defp package_status(%{kind: :package}, _vuln), do: :unknown
  defp package_status(_a, vuln), do: vuln.fix_status

  defp non_empty([]), do: [nil]
  defp non_empty(list), do: list

  defp scores_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100">
      <h2 class="border-b border-base-300 px-5 py-3 font-semibold">CVSS scores</h2>
      <div class="overflow-x-auto">
        <table class="table table-sm" id="cvss-scores">
          <thead>
            <tr class="text-xs uppercase tracking-wider text-base-content/55">
              <th>Source</th>
              <th>Version</th>
              <th>Score</th>
              <th>Vector</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={s <- @detail.scores}>
              <td class="whitespace-nowrap">
                {Format.source_label(s.type)}
                <div :if={s.source} class="text-[0.7rem] text-base-content/50">{s.source}</div>
              </td>
              <td class="font-mono text-xs">v{s.version}</td>
              <td class="whitespace-nowrap">
                <.severity_badge
                  severity={Vulsweb.Vuls.Scoring.severity(s.score)}
                  score={if(s.calculated_by_severity, do: nil, else: s.score)}
                />
                <span :if={s.calculated_by_severity} class="ml-1 text-xs text-base-content/55">
                  {s.severity}
                </span>
              </td>
              <td class="break-all font-mono text-[0.7rem] text-base-content/70">
                {s.vector || "—"}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
    """
  end

  defp kev_card(assigns) do
    ~H"""
    <section class="rounded-box border border-error/30 bg-error/5 p-5">
      <h2 class="flex items-center gap-2 font-semibold text-error">
        <.icon name="lucide-shield-alert" class="size-5" /> Known exploited vulnerability
      </h2>
      <div :for={k <- @kevs} class="mt-3 space-y-1 text-sm">
        <div class="font-medium">
          {String.upcase(k.type || "kev")}: {k.name || "Listed"}
        </div>
        <p :if={k.description} class="text-base-content/75">{k.description}</p>
        <p :if={k.required_action} class="text-base-content/75">
          <span class="font-medium">Required action:</span> {k.required_action}
        </p>
        <div class="flex flex-wrap gap-x-5 text-xs text-base-content/60">
          <span :if={k.date_added}>Added {Format.date(k.date_added)}</span>
          <span :if={k.due_date}>Due {Format.date(k.due_date)}</span>
          <span :if={k.ransomware}>Ransomware use: {k.ransomware}</span>
        </div>
      </div>
    </section>
    """
  end

  defp exploits_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100">
      <h2 class="flex items-center gap-2 border-b border-base-300 px-5 py-3 font-semibold">
        <.icon name="lucide-zap" class="size-5 text-warning" /> Exploits
      </h2>
      <ul class="divide-y divide-base-300">
        <li :for={m <- @detail.metasploits} class="px-5 py-3 text-sm">
          <div class="flex items-center gap-2">
            <span class="rounded bg-warning/15 px-1.5 text-[0.68rem] font-bold text-warning">
              METASPLOIT
            </span>
            <span class="font-mono text-xs">{m.name}</span>
          </div>
          <p :if={m.title} class="mt-1 text-base-content/75">{m.title}</p>
          <a
            :for={u <- m.urls}
            href={u}
            target="_blank"
            rel="noopener"
            class="link link-hover mt-1 block break-all text-xs text-primary"
          >
            {u}
          </a>
        </li>
        <li :for={e <- @detail.exploits} class="px-5 py-3 text-sm">
          <div class="flex items-center gap-2">
            <span class="rounded bg-base-200 px-1.5 text-[0.68rem] font-bold uppercase text-base-content/70">
              {e.type}
            </span>
            <a
              :if={e.url}
              href={e.url}
              target="_blank"
              rel="noopener"
              class="link link-hover break-all text-xs text-primary"
            >
              {e.url}
            </a>
          </div>
          <p :if={e.description} class="mt-1 line-clamp-3 text-base-content/75">
            {e.description}
          </p>
        </li>
      </ul>
    </section>
    """
  end

  defp sources_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100">
      <h2 class="border-b border-base-300 px-5 py-3 font-semibold">Descriptions by source</h2>
      <div class="divide-y divide-base-300">
        <details
          :for={{c, i} <- Enum.with_index(@detail.contents)}
          open={i == 0}
          class="group px-5 py-3"
        >
          <summary class="flex cursor-pointer list-none items-center justify-between gap-2 text-sm font-medium [&::-webkit-details-marker]:hidden">
            <span>
              {Format.source_label(c.type)}
              <span :if={c.source} class="font-normal text-base-content/50">· {c.source}</span>
            </span>
            <span class="flex items-center gap-3 text-xs font-normal text-base-content/55">
              <span :if={c.last_modified}>updated {Format.date(c.last_modified)}</span>
              <.icon name="lucide-chevron-down" class="size-4 transition group-open:rotate-180" />
            </span>
          </summary>
          <p :if={c.title && c.title != @detail.cve_id} class="mt-2 text-sm font-medium">
            {c.title}
          </p>
          <p class="mt-2 whitespace-pre-line text-sm text-base-content/75">
            {c.summary || "No description from this source."}
          </p>
          <a
            :if={c.source_link}
            href={c.source_link}
            target="_blank"
            rel="noopener"
            class="link link-hover mt-2 inline-block break-all text-xs text-primary"
          >
            {c.source_link}
          </a>
        </details>
      </div>
    </section>
    """
  end

  defp facts_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100 p-5">
      <dl class="grid grid-cols-[8rem_1fr] gap-y-2.5 text-sm">
        <dt class="text-base-content/55">Max CVSS</dt>
        <dd :if={@detail.max}>
          <span class="font-mono font-semibold">{Format.score(@detail.max.score)}</span>
          <span class="text-xs text-base-content/55">
            v{@detail.max.version} · {Format.source_label(@detail.max.type)}
          </span>
        </dd>
        <dd :if={!@detail.max}>—</dd>
        <dt class="text-base-content/55">Attack vector</dt>
        <dd>{Vulsweb.Vuls.Scoring.attack_vector_label(@detail.attack_vector) || "—"}</dd>
        <dt class="text-base-content/55">Published</dt>
        <dd>{Format.date(@detail.published)}</dd>
        <dt class="text-base-content/55">Last modified</dt>
        <dd>{Format.date(@detail.last_modified)}</dd>
        <dt class="text-base-content/55">Hosts</dt>
        <dd>
          {length(@row.hosts)}
          <span class="text-xs text-success">({@row.fixable_hosts} fixable)</span>
        </dd>
        <%= if @detail.ssvc do %>
          <dt class="text-base-content/55">SSVC</dt>
          <dd class="text-xs leading-5">
            <div :if={@detail.ssvc.exploitation}>Exploitation: {@detail.ssvc.exploitation}</div>
            <div :if={@detail.ssvc.automatable}>Automatable: {@detail.ssvc.automatable}</div>
            <div :if={@detail.ssvc.technical_impact}>
              Impact: {@detail.ssvc.technical_impact}
            </div>
          </dd>
        <% end %>
      </dl>
    </section>
    """
  end

  defp cwe_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100 p-5">
      <h2 class="mb-3 font-semibold">Weaknesses</h2>
      <ul class="space-y-2 text-sm">
        <li :for={c <- @cwes}>
          <a
            :if={c.url}
            href={c.url}
            target="_blank"
            rel="noopener"
            class="font-mono text-xs font-semibold text-primary hover:underline"
          >
            {c.id}
          </a>
          <span :if={!c.url} class="font-mono text-xs font-semibold">{c.id}</span>
          <span
            :if={c.top25 != []}
            class="ml-1 rounded bg-error/10 px-1 text-[0.65rem] font-semibold text-error"
          >
            CWE TOP 25
          </span>
          <div :if={c.name} class="text-base-content/75">{c.name}</div>
        </li>
      </ul>
    </section>
    """
  end

  defp advisories_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100 p-5">
      <h2 class="mb-3 font-semibold">Distro advisories</h2>
      <ul class="space-y-2 text-sm">
        <li :for={a <- @advisories}>
          <span class="font-mono text-xs font-semibold">{a.id}</span>
          <span :if={a.severity} class="ml-1 text-xs text-base-content/60">{a.severity}</span>
          <div :if={a.description} class="text-xs text-base-content/70">{a.description}</div>
        </li>
      </ul>
    </section>
    """
  end

  defp mitigations_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100 p-5">
      <h2 class="mb-3 font-semibold">Mitigations</h2>
      <ul class="space-y-3 text-sm">
        <li :for={m <- @mitigations}>
          <div class="text-xs text-base-content/55">{Format.source_label(m.type)}</div>
          <p :if={m.text} class="whitespace-pre-line text-base-content/80">{m.text}</p>
          <a
            :if={m.url}
            href={m.url}
            target="_blank"
            rel="noopener"
            class="link link-hover break-all text-xs text-primary"
          >
            {m.url}
          </a>
        </li>
      </ul>
    </section>
    """
  end

  defp references_card(assigns) do
    ~H"""
    <section class="rounded-box border border-base-300 bg-base-100 p-5">
      <h2 class="mb-3 font-semibold">
        References <span class="font-normal text-base-content/50">({length(@references)})</span>
      </h2>
      <ul class="max-h-96 space-y-1.5 overflow-y-auto text-xs">
        <li :for={r <- @references} class="break-all">
          <a href={r.link} target="_blank" rel="noopener" class="link link-hover text-primary">
            {r.link}
          </a>
          <span :if={r.tags != []} class="text-base-content/50">· {Enum.join(r.tags, ", ")}</span>
        </li>
      </ul>
    </section>
    """
  end
end
