defmodule Vulsweb.Results.Aggregate do
  @moduledoc """
  Cross-host views over the latest scan of every host.
  """

  alias Vulsweb.Vuls.{Scan, Scoring}

  @type cve_row :: %{
          cve_id: String.t(),
          score: float() | nil,
          severity: Scoring.severity(),
          cvss_version: String.t() | nil,
          summary: String.t() | nil,
          kev: boolean(),
          exploits: non_neg_integer(),
          attack_vector: String.t() | nil,
          published: Date.t() | nil,
          hosts: [String.t()],
          packages: [String.t()],
          fixable_hosts: non_neg_integer(),
          unfixed_hosts: non_neg_integer()
        }

  @doc "One row per CVE across all hosts, most severe first."
  @spec cves([Scan.t()]) :: [cve_row()]
  def cves(scans) do
    scans
    |> Enum.flat_map(fn %Scan{host: host, vulns: vulns} ->
      Enum.map(vulns || [], &{host, &1})
    end)
    |> Enum.group_by(fn {_host, v} -> v.cve_id end)
    |> Enum.map(fn {cve_id, entries} ->
      vulns = Enum.map(entries, &elem(&1, 1))
      # The max score is per host (distro sources differ), take the worst.
      top = Enum.max_by(vulns, &(&1.score || 0))

      %{
        cve_id: cve_id,
        score: top.score,
        severity: top.severity,
        cvss_version: top.cvss_version,
        summary: Enum.find_value(vulns, & &1.summary),
        kev: Enum.any?(vulns, & &1.kev),
        exploits: vulns |> Enum.map(&(&1.exploits + &1.metasploits)) |> Enum.max(),
        attack_vector: Enum.find_value(vulns, & &1.attack_vector),
        published: Enum.find_value(vulns, & &1.published),
        hosts: entries |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> Enum.sort(),
        packages:
          vulns
          |> Enum.flat_map(fn v -> Enum.map(v.affected, & &1.name) end)
          |> Enum.uniq()
          |> Enum.sort(),
        fixable_hosts: Enum.count(vulns, &(&1.fix_status == :fixable)),
        unfixed_hosts: Enum.count(vulns, &(&1.fix_status == :unfixed))
      }
    end)
    |> Enum.sort_by(&{-(&1.score || 0), -length(&1.hosts), &1.cve_id})
  end

  @doc "Fleet-wide totals from the light host summaries."
  def totals(hosts, cves) do
    by_sev = Enum.frequencies_by(cves, & &1.severity)

    %{
      hosts: length(hosts),
      cves: length(cves),
      critical: Map.get(by_sev, :critical, 0),
      high: Map.get(by_sev, :high, 0),
      medium: Map.get(by_sev, :medium, 0),
      low: Map.get(by_sev, :low, 0),
      unknown: Map.get(by_sev, :unknown, 0),
      kev: Enum.count(cves, & &1.kev),
      exploitable: Enum.count(cves, &(&1.exploits > 0)),
      fixable: Enum.count(cves, &(&1.fixable_hosts > 0)),
      findings: hosts |> Enum.map(& &1.counts.total) |> Enum.sum(),
      reboot_required: Enum.count(hosts, & &1.reboot_required),
      with_errors: Enum.count(hosts, &(&1.errors != [] or &1.parse_error != nil))
    }
  end
end
