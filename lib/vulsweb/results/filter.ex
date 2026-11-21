defmodule Vulsweb.Results.Filter do
  @moduledoc """
  Filtering, sorting and paging of CVE rows from URL params. Used by the
  LiveViews and the CSV export so both always agree.

  Params (all optional, string keys):

    * `q`       - search in CVE id, summary, package names (and hosts for fleet rows)
    * `sev`     - comma separated severities, e.g. `critical,high`
    * `fix`     - `fixable` | `unfixed` | `unknown`
    * `kev`     - `"1"` to only keep CVEs in a KEV catalog
    * `exploit` - `"1"` to only keep CVEs with public exploits
    * `sort`    - column, `dir` - `asc` | `desc`
    * `page`    - 1-based page
  """

  alias Vulsweb.Vuls.Vuln

  @severities ~w(critical high medium low unknown)
  @sev_rank %{critical: 4, high: 3, medium: 2, low: 1, unknown: 0}

  @doc "Normalized params with defaults."
  def normalize(params, default_sort \\ "score") do
    %{
      "q" => params |> Map.get("q", "") |> to_string() |> String.trim(),
      "sev" => params |> Map.get("sev", "") |> parse_sev() |> Enum.join(","),
      "fix" => if(params["fix"] in ~w(fixable unfixed unknown), do: params["fix"], else: ""),
      "kev" => if(params["kev"] in ["1", "true", "on"], do: "1", else: ""),
      "exploit" => if(params["exploit"] in ["1", "true", "on"], do: "1", else: ""),
      "sort" => params |> Map.get("sort", default_sort) |> to_string(),
      "dir" => if(params["dir"] == "asc", do: "asc", else: "desc"),
      "page" => parse_page(params["page"])
    }
  end

  @doc "Filters and sorts the per-host vuln rows."
  @spec vulns([Vuln.t()], map()) :: [Vuln.t()]
  def vulns(vulns, params) do
    q = String.downcase(params["q"])
    sevs = selected_sev(params)

    vulns
    |> Enum.filter(fn v ->
      (sevs == nil or v.severity in sevs) and
        (params["fix"] == "" or Atom.to_string(v.fix_status) == params["fix"]) and
        (params["kev"] == "" or v.kev) and
        (params["exploit"] == "" or v.exploits + v.metasploits > 0) and
        (q == "" or
           matches?(q, [v.cve_id, v.summary | Vuln.affected_names(v)]))
    end)
    |> sort(params, fn
      "cve" -> & &1.cve_id
      "package" -> &(&1 |> Vuln.affected_names() |> List.first() || "")
      "fix" -> &fix_rank(&1.fix_status)
      "published" -> &date_key(&1.published)
      _score -> &{&1.score || -1.0, @sev_rank[&1.severity], &1.cve_id}
    end)
  end

  @doc "Filters and sorts the fleet-wide CVE rows."
  def cves(rows, params) do
    q = String.downcase(params["q"])
    sevs = selected_sev(params)

    rows
    |> Enum.filter(fn r ->
      (sevs == nil or r.severity in sevs) and
        (params["fix"] != "fixable" or r.fixable_hosts > 0) and
        (params["fix"] != "unfixed" or r.unfixed_hosts > 0) and
        (params["fix"] != "unknown" or r.fixable_hosts + r.unfixed_hosts < length(r.hosts)) and
        (params["kev"] == "" or r.kev) and
        (params["exploit"] == "" or r.exploits > 0) and
        (q == "" or matches?(q, [r.cve_id, r.summary | r.packages ++ r.hosts]))
    end)
    |> sort(params, fn
      "cve" -> & &1.cve_id
      "hosts" -> &{length(&1.hosts), &1.score || -1.0}
      "published" -> &date_key(&1.published)
      _score -> &{&1.score || -1.0, length(&1.hosts), &1.cve_id}
    end)
  end

  @doc "Filters packages: `q` on name, `upgradable`/`vulnerable` toggles."
  def packages(packages, params) do
    q = params |> Map.get("q", "") |> String.downcase() |> String.trim()

    Enum.filter(packages, fn p ->
      (q == "" or String.contains?(String.downcase(p.name), q)) and
        (params["upgradable"] != "1" or p.new_version != nil) and
        (params["vulnerable"] != "1" or p.vulns > 0)
    end)
  end

  @doc "Returns `{rows_for_page, page, pages}`."
  def paginate(rows, page, per_page) do
    total = length(rows)
    pages = max(div(total + per_page - 1, per_page), 1)
    page = page |> max(1) |> min(pages)
    {Enum.slice(rows, (page - 1) * per_page, per_page), page, pages}
  end

  @doc "Severity buckets currently selected (as a list of strings)."
  def sev_list(params), do: parse_sev(params["sev"] || "")

  @doc "Toggles one severity in the `sev` param."
  def toggle_sev(params, sev) do
    current = sev_list(params)
    next = if sev in current, do: current -- [sev], else: current ++ [sev]

    next
    |> Enum.filter(&(&1 in @severities))
    |> Enum.sort_by(&Enum.find_index(@severities, fn s -> s == &1 end))
    |> Enum.join(",")
  end

  defp sort(rows, params, key_fun) do
    key = key_fun.(params["sort"])
    rows = Enum.sort_by(rows, key)
    if params["dir"] == "desc", do: Enum.reverse(rows), else: rows
  end

  defp selected_sev(params) do
    case parse_sev(params["sev"]) do
      [] -> nil
      list -> Enum.map(list, &String.to_existing_atom/1)
    end
  end

  defp parse_sev(nil), do: []

  defp parse_sev(s) when is_binary(s) do
    s
    |> String.split(",", trim: true)
    |> Enum.map(&String.trim/1)
    |> Enum.filter(&(&1 in @severities))
    |> Enum.uniq()
  end

  defp parse_sev(_), do: []

  defp parse_page(p) when is_binary(p) do
    case Integer.parse(p) do
      {n, ""} when n > 0 -> n
      _ -> 1
    end
  end

  defp parse_page(p) when is_integer(p) and p > 0, do: p
  defp parse_page(_), do: 1

  defp matches?(q, fields) do
    Enum.any?(fields, fn f -> is_binary(f) and String.contains?(String.downcase(f), q) end)
  end

  defp fix_rank(:fixable), do: 2
  defp fix_rank(:unknown), do: 1
  defp fix_rank(:unfixed), do: 0

  defp date_key(nil), do: 0
  defp date_key(%Date{} = d), do: Date.to_gregorian_days(d)
end
