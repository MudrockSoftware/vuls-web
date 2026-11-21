defmodule VulswebWeb.VulnComponents do
  @moduledoc "Building blocks for the vulnerability views."

  use Phoenix.Component

  use Phoenix.VerifiedRoutes,
    endpoint: VulswebWeb.Endpoint,
    router: VulswebWeb.Router,
    statics: VulswebWeb.static_paths()

  import VulswebWeb.CoreComponents, only: [icon: 1]
  alias VulswebWeb.Format

  @sev_bg %{
    critical: "bg-sev-critical",
    high: "bg-sev-high",
    medium: "bg-sev-medium",
    low: "bg-sev-low",
    unknown: "bg-sev-none"
  }

  @sev_text %{
    critical: "text-sev-critical",
    high: "text-sev-high",
    medium: "text-sev-medium",
    low: "text-sev-low",
    unknown: "text-sev-none"
  }

  def sev_bg(sev), do: Map.fetch!(@sev_bg, sev)
  def sev_text(sev), do: Map.fetch!(@sev_text, sev)

  @doc "Severity pill with optional score."
  attr :severity, :atom, required: true
  attr :score, :any, default: nil
  attr :class, :any, default: nil

  def severity_badge(assigns) do
    ~H"""
    <span class={[
      "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold text-sev-content whitespace-nowrap",
      sev_bg(@severity),
      @class
    ]}>
      <span :if={@score} class="font-mono tabular-nums">{Format.score(@score)}</span>
      <span class={[@score && "opacity-90 font-medium"]}>{Format.severity_label(@severity)}</span>
    </span>
    """
  end

  @doc "Compact per-severity counters (C / H / M / L / ?)."
  attr :counts, :map, required: true
  attr :size, :string, default: "sm"

  def severity_counts(assigns) do
    ~H"""
    <div class="flex items-center gap-1">
      <span
        :for={sev <- [:critical, :high, :medium, :low, :unknown]}
        title={Format.severity_label(sev)}
        class={[
          "inline-flex min-w-8 justify-center rounded px-1.5 py-0.5 font-mono text-xs tabular-nums",
          if(Map.get(@counts, sev, 0) > 0,
            do: [sev_bg(sev), "text-sev-content font-semibold"],
            else: "bg-base-200 text-base-content/35"
          )
        ]}
      >
        {Map.get(@counts, sev, 0)}
      </span>
    </div>
    """
  end

  @doc "Stacked horizontal bar of severity counts."
  attr :counts, :map, required: true
  attr :class, :any, default: "h-2"

  def severity_bar(assigns) do
    total =
      [:critical, :high, :medium, :low, :unknown]
      |> Enum.map(&Map.get(assigns.counts, &1, 0))
      |> Enum.sum()

    assigns = assign(assigns, :total, total)

    ~H"""
    <div class={["flex w-full overflow-hidden rounded-full bg-base-200", @class]}>
      <div
        :for={sev <- [:critical, :high, :medium, :low, :unknown]}
        :if={@total > 0 and Map.get(@counts, sev, 0) > 0}
        class={[sev_bg(sev), "h-full transition-all duration-500"]}
        style={"width: #{Map.get(@counts, sev, 0) / @total * 100}%"}
        title={"#{Format.severity_label(sev)}: #{Map.get(@counts, sev, 0)}"}
      />
    </div>
    """
  end

  @doc "Fix availability badge."
  attr :status, :atom, required: true

  def fix_badge(assigns) do
    ~H"""
    <span class={[
      "inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium",
      @status == :fixable && "text-success",
      @status == :unfixed && "text-base-content/60",
      @status == :unknown && "text-base-content/45"
    ]}>
      <.icon
        name={
          case @status do
            :fixable -> "lucide-circle-arrow-up"
            :unfixed -> "lucide-clock"
            :unknown -> "lucide-circle-help"
          end
        }
        class="size-4"
      />
      {Format.fix_label(@status)}
    </span>
    """
  end

  @doc "KEV / exploit markers."
  attr :kev, :boolean, default: false
  attr :exploits, :integer, default: 0

  def threat_tags(assigns) do
    ~H"""
    <span class="inline-flex items-center gap-1">
      <span
        :if={@kev}
        title="Listed in a Known Exploited Vulnerabilities catalog"
        class="rounded border border-error/40 bg-error/10 px-1.5 py-px text-[0.68rem] font-bold tracking-wide text-error"
      >
        KEV
      </span>
      <span
        :if={@exploits > 0}
        title={"#{@exploits} public exploit(s) / Metasploit module(s)"}
        class="inline-flex items-center gap-0.5 rounded border border-warning/40 bg-warning/10 px-1.5 py-px text-[0.68rem] font-bold tracking-wide text-warning"
      >
        <.icon name="lucide-zap" class="size-3" /> EXPLOIT
      </span>
    </span>
    """
  end

  @doc "Big number tile."
  attr :label, :string, required: true
  attr :value, :any, required: true
  attr :icon, :string, default: nil
  attr :tone, :string, default: nil
  attr :hint, :string, default: nil
  attr :navigate, :string, default: nil

  def stat(assigns) do
    ~H"""
    <.link
      navigate={@navigate}
      class={[
        "group block rounded-box border border-base-300 bg-base-100 p-4 transition",
        @navigate && "hover:border-primary/40 hover:shadow-sm"
      ]}
    >
      <div class="flex items-center justify-between text-xs font-medium uppercase tracking-wider text-base-content/55">
        {@label}
        <.icon :if={@icon} name={@icon} class={["size-4", @tone || "text-base-content/40"]} />
      </div>
      <div class={["mt-2 text-3xl font-semibold tabular-nums tracking-tight", @tone]}>
        {Format.number(@value)}
      </div>
      <div :if={@hint} class="mt-1 text-xs text-base-content/55">{@hint}</div>
    </.link>
    """
  end

  @doc "Relative time with the absolute time rendered in the browser's timezone on hover."
  attr :at, :any, required: true
  attr :id, :string, required: true
  attr :class, :any, default: nil

  def time_ago(assigns) do
    ~H"""
    <time
      :if={@at}
      id={@id}
      datetime={Format.iso(@at)}
      title={Format.datetime(@at)}
      class={@class}
    >
      {Format.ago(@at)}
    </time>
    <span :if={!@at} class={@class}>—</span>
    """
  end

  @doc "Absolute time, localized client side."
  attr :at, :any, required: true
  attr :id, :string, required: true
  attr :class, :any, default: nil

  def local_time(assigns) do
    ~H"""
    <time
      :if={@at}
      id={@id}
      phx-hook="LocalTime"
      data-iso={Format.iso(@at)}
      datetime={Format.iso(@at)}
      class={@class}
    >
      {Format.datetime(@at)}
    </time>
    <span :if={!@at} class={@class}>—</span>
    """
  end

  @doc "Sortable column header that patches the URL."
  attr :field, :string, required: true
  attr :sort, :string, required: true
  attr :dir, :string, required: true
  attr :params, :map, required: true
  attr :path, :string, required: true
  attr :class, :any, default: nil
  slot :inner_block, required: true

  def sort_header(assigns) do
    active = assigns.sort == assigns.field
    next_dir = if active and assigns.dir == "desc", do: "asc", else: "desc"

    params =
      Map.merge(assigns.params, %{"sort" => assigns.field, "dir" => next_dir, "page" => nil})

    assigns =
      assigns
      |> assign(:active, active)
      |> assign(:href, assigns.path <> query(params))

    ~H"""
    <th class={@class}>
      <.link
        patch={@href}
        class={[
          "inline-flex items-center gap-1 hover:text-base-content",
          @active && "text-base-content"
        ]}
      >
        {render_slot(@inner_block)}
        <.icon
          name={
            cond do
              !@active -> "lucide-chevrons-up-down"
              @dir == "asc" -> "lucide-chevron-up"
              true -> "lucide-chevron-down"
            end
          }
          class={["size-3.5", !@active && "opacity-40"]}
        />
      </.link>
    </th>
    """
  end

  @doc "Empty state block."
  attr :icon, :string, default: "lucide-inbox"
  attr :title, :string, required: true
  slot :inner_block

  def empty(assigns) do
    ~H"""
    <div class="flex flex-col items-center justify-center rounded-box border border-dashed border-base-300 px-6 py-14 text-center">
      <div class="flex size-12 items-center justify-center rounded-full bg-base-200">
        <.icon name={@icon} class="size-6 text-base-content/50" />
      </div>
      <h3 class="mt-4 text-base font-semibold">{@title}</h3>
      <div class="mt-1 max-w-md text-sm text-base-content/60">{render_slot(@inner_block)}</div>
    </div>
    """
  end

  @doc "Pager for client-side sliced lists."
  attr :page, :integer, required: true
  attr :pages, :integer, required: true
  attr :total, :integer, required: true
  attr :params, :map, required: true
  attr :path, :string, required: true

  def pager(assigns) do
    ~H"""
    <div :if={@pages > 1} class="flex items-center justify-between gap-4 pt-4 text-sm">
      <span class="text-base-content/60">
        Page {@page} of {@pages} · {Format.number(@total)} rows
      </span>
      <div class="join">
        <.link
          patch={@path <> query(Map.put(@params, "page", max(@page - 1, 1)))}
          class={["btn join-item btn-sm", @page <= 1 && "btn-disabled"]}
        >
          <.icon name="lucide-chevron-left" class="size-4" />
        </.link>
        <.link
          patch={@path <> query(Map.put(@params, "page", min(@page + 1, @pages)))}
          class={["btn join-item btn-sm", @page >= @pages && "btn-disabled"]}
        >
          <.icon name="lucide-chevron-right" class="size-4" />
        </.link>
      </div>
    </div>
    """
  end

  @doc """
  Filter bar for CVE tables. Emits `filter` (form change) events; severity
  chips are patch links. `params` are the normalized filter params.
  """
  attr :id, :string, required: true
  attr :params, :map, required: true
  attr :path, :string, required: true
  attr :counts, :map, default: nil, doc: "optional per-severity counts shown on chips"
  attr :placeholder, :string, default: "Search CVE, package, text"
  attr :fix_label, :string, default: "Fix status"
  attr :shown, :integer, required: true
  attr :total, :integer, required: true
  slot :actions

  def filter_bar(assigns) do
    selected = Vulsweb.Results.Filter.sev_list(assigns.params)
    filtering? = Enum.any?(~w(q sev fix kev exploit), &(assigns.params[&1] not in ["", nil]))
    assigns = assign(assigns, selected: selected, filtering?: filtering?)

    ~H"""
    <div class="space-y-3">
      <form
        id={@id}
        phx-change="filter"
        phx-submit="filter"
        class="flex flex-wrap items-center gap-2"
      >
        <label class="input input-sm w-full sm:w-72">
          <.icon name="lucide-search" class="size-4 opacity-50" />
          <input
            type="search"
            name="q"
            value={@params["q"]}
            placeholder={@placeholder}
            phx-debounce="250"
            data-search-input
            autocomplete="off"
          />
          <kbd class="kbd kbd-xs hidden sm:inline-flex">/</kbd>
        </label>
        <select name="fix" class="select select-sm w-auto">
          <option value="" selected={@params["fix"] == ""}>{@fix_label}: any</option>
          <option value="fixable" selected={@params["fix"] == "fixable"}>Fix available</option>
          <option value="unfixed" selected={@params["fix"] == "unfixed"}>No fix yet</option>
          <option value="unknown" selected={@params["fix"] == "unknown"}>Unknown</option>
        </select>
        <label class="label cursor-pointer gap-1.5 rounded-field border border-base-300 px-2.5 py-1 text-sm">
          <input type="hidden" name="kev" value="" />
          <input
            type="checkbox"
            name="kev"
            value="1"
            checked={@params["kev"] == "1"}
            class="checkbox checkbox-xs checkbox-error"
          /> KEV
        </label>
        <label class="label cursor-pointer gap-1.5 rounded-field border border-base-300 px-2.5 py-1 text-sm">
          <input type="hidden" name="exploit" value="" />
          <input
            type="checkbox"
            name="exploit"
            value="1"
            checked={@params["exploit"] == "1"}
            class="checkbox checkbox-xs checkbox-warning"
          /> Exploit
        </label>
        <input type="hidden" name="sev" value={@params["sev"]} />
        <input type="hidden" name="sort" value={@params["sort"]} />
        <input type="hidden" name="dir" value={@params["dir"]} />
        <div class="ml-auto flex items-center gap-2">
          {render_slot(@actions)}
        </div>
      </form>
      <div class="flex flex-wrap items-center gap-1.5">
        <.link
          :for={sev <- ~w(critical high medium low unknown)}
          patch={@path <> query(Map.merge(@params, %{"sev" => Vulsweb.Results.Filter.toggle_sev(@params, sev), "page" => nil}))}
          class={[
            "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium transition",
            if(sev in @selected,
              do: [sev_bg(String.to_existing_atom(sev)), "border-transparent text-sev-content"],
              else: "border-base-300 hover:border-base-content/30"
            )
          ]}
        >
          <span
            :if={sev not in @selected}
            class={["size-2 rounded-full", sev_bg(String.to_existing_atom(sev))]}
          />
          {Format.severity_label(String.to_existing_atom(sev))}
          <span :if={@counts} class="font-mono tabular-nums opacity-75">
            {Map.get(@counts, String.to_existing_atom(sev), 0)}
          </span>
        </.link>
        <span class="ml-2 text-xs text-base-content/55">
          Showing {Format.number(@shown)} of {Format.number(@total)}
        </span>
        <.link
          :if={@filtering?}
          patch={@path <> query(Map.take(@params, ["sort", "dir"]))}
          class="link link-hover ml-1 text-xs text-primary"
        >
          Clear filters
        </.link>
      </div>
    </div>
    """
  end

  @doc "Merges a `filter` form event into params (keeps page reset)."
  def merge_filter(params, form) do
    params
    |> Map.merge(Map.take(form, ~w(q fix kev exploit sev sort dir)))
    |> Map.put("page", nil)
  end

  @doc "Builds `?a=b` from a params map, dropping empty values."
  def query(params) do
    params
    |> Enum.reject(fn {_k, v} -> v in [nil, "", false, []] end)
    |> Enum.sort()
    |> case do
      [] -> ""
      list -> "?" <> URI.encode_query(list)
    end
  end
end
