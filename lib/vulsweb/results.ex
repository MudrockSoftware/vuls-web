defmodule Vulsweb.Results do
  @moduledoc """
  Read API over the indexed vuls results (see `Vulsweb.Results.Store`).
  """

  alias Vulsweb.Results.{Aggregate, Store}
  alias Vulsweb.Vuls.{Compat, CveDetail, Report, Scan}

  # How many result files (distinct OS families) to sample for CVE details.
  @detail_samples 4

  @doc "Subscribes the caller to `{:results_updated, hosts}` messages."
  def subscribe, do: Phoenix.PubSub.subscribe(Vulsweb.PubSub, Store.topic())

  @doc "Indexer status: `%{dir, state, error, refreshed_at, files, failed}`."
  def status, do: lookup(Store.meta_table(), :status, 2) || %{state: :starting}

  @doc "Triggers a synchronous re-scan."
  def refresh, do: Store.refresh()

  @doc "Light summaries (no CVE rows) of the latest scan of every host."
  @spec hosts() :: [Scan.t()]
  def hosts do
    Store.hosts_table()
    |> :ets.select([{{:_, :"$1", :_}, [], [:"$1"]}])
    |> Enum.sort_by(& &1.host)
  rescue
    ArgumentError -> []
  end

  @doc "Full latest scan of `host`, or `nil`."
  @spec host(String.t()) :: Scan.t() | nil
  def host(host), do: lookup(Store.hosts_table(), host, 3)

  @doc "All scans of `host`, newest first (counts only)."
  @spec history(String.t()) :: [Scan.t()]
  def history(host), do: lookup(Store.history_table(), host, 2) || []

  @doc """
  Full summary of a specific scan of `host` (by scan id), parsed on demand.
  Returns the latest scan without re-parsing when `id` is the latest one.
  """
  @spec scan(String.t(), String.t()) :: {:ok, Scan.t()} | {:error, :not_found}
  def scan(host, id) do
    case host(host) do
      %Scan{id: ^id} = latest ->
        {:ok, latest}

      _ ->
        case Enum.find(history(host), &(&1.id == id)) do
          nil -> {:error, :not_found}
          meta -> {:ok, load(meta)}
        end
    end
  end

  @doc """
  New and resolved CVEs of `scan` compared to the scan before it.
  Returns `nil` when there is no previous scan.
  """
  def diff(%Scan{host: host, id: id} = scan) do
    history = history(host)

    with idx when is_integer(idx) <- Enum.find_index(history, &(&1.id == id)),
         %Scan{} = prev_meta <- Enum.at(history, idx + 1) do
      prev = load(prev_meta)
      prev_ids = MapSet.new(prev.vulns, & &1.cve_id)
      cur_ids = MapSet.new(scan.vulns, & &1.cve_id)

      %{
        previous: Scan.strip(prev),
        added: Enum.reject(scan.vulns, &MapSet.member?(prev_ids, &1.cve_id)),
        resolved: Enum.reject(prev.vulns, &MapSet.member?(cur_ids, &1.cve_id))
      }
    else
      _ -> nil
    end
  end

  @doc "One row per CVE across the latest scans of all hosts."
  @spec cves() :: [Aggregate.cve_row()]
  def cves, do: lookup(Store.meta_table(), :cves, 2) || []

  @doc "Fleet-wide totals."
  def totals, do: Aggregate.totals(hosts(), cves())

  @doc """
  Details of `cve_id` across hosts: `{:ok, %{detail, row, hosts}}` where
  `hosts` is a list of `{scan, vuln}` for every host affected by it.
  """
  def cve(cve_id) do
    case Enum.find(cves(), &(&1.cve_id == cve_id)) do
      nil ->
        {:error, :not_found}

      row ->
        affected =
          for h <- row.hosts,
              %Scan{} = scan <- [host(h)],
              vuln = Enum.find(scan.vulns, &(&1.cve_id == cve_id)),
              do: {Scan.strip(scan), vuln}

        samples =
          affected
          |> Enum.map(&elem(&1, 0))
          |> Enum.uniq_by(& &1.family)
          |> Enum.take(@detail_samples)

        {raws, cwe_dict} =
          Enum.reduce(samples, {[], %{}}, fn scan, {raws, dict} ->
            case read(scan.path) do
              {:ok, doc} ->
                raw = get_in(doc, ["scannedCves", cve_id])
                d = if is_map(doc["cweDict"]), do: doc["cweDict"], else: %{}
                {if(is_map(raw), do: [raw | raws], else: raws), Map.merge(d, dict)}

              _ ->
                {raws, dict}
            end
          end)

        family = samples |> List.first() |> then(&(&1 && &1.family))

        detail =
          case Enum.reverse(raws) do
            [] -> nil
            raws -> CveDetail.build(cve_id, CveDetail.merge(raws), cwe_dict, family)
          end

        {:ok, %{row: row, detail: detail, hosts: affected}}
    end
  end

  defp load(%Scan{} = meta) do
    file = Map.take(meta, [:id, :host, :dir, :path, :mtime, :size])

    case read(meta.path) do
      {:ok, doc} -> Report.summarize(doc, file)
      {:error, reason} -> Report.failed(file, reason)
    end
  end

  defp read(path), do: Compat.read_file(path)

  defp lookup(table, key, pos) do
    :ets.lookup_element(table, key, pos, nil)
  rescue
    ArgumentError -> nil
  end
end
