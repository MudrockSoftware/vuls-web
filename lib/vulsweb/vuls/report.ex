defmodule Vulsweb.Vuls.Report do
  @moduledoc """
  Turns a decoded vuls `ScanResult` JSON document into a `Vulsweb.Vuls.Scan`.

  Works with the JSON written by vuls v0.19+ (`jsonVersion` 4) up to the
  current releases; unknown or missing fields are tolerated.
  """

  alias Vulsweb.Vuls.{Scan, Scoring, Vuln}

  @summary_limit 400

  @doc """
  Summarizes `doc` (a decoded result file). `file` carries the location
  metadata: `:id`, `:host`, `:dir`, `:path`, `:mtime`, `:size`.
  """
  @spec summarize(map(), map()) :: Scan.t()
  def summarize(doc, file) when is_map(doc) do
    packages = map(doc["packages"])
    family = blank(doc["family"])
    kernel = map(doc["runningKernel"])

    vulns =
      doc["scannedCves"]
      |> map()
      |> Enum.map(fn {cve_id, vuln} -> vuln(cve_id, map(vuln), packages, family) end)
      |> Enum.sort_by(&{-(&1.score || 0), &1.cve_id})

    pkg_rows = package_rows(packages, vulns)

    %Scan{
      id: file.id,
      host: file.host,
      dir: file.dir,
      path: file.path,
      mtime: file.mtime,
      size: file.size,
      server_name: blank(doc["serverName"]),
      container: blank(get_in(doc, ["container", "name"])),
      family: family,
      release: blank(doc["release"]),
      kernel_release: blank(kernel["release"]),
      kernel_version: blank(kernel["version"]),
      reboot_required: kernel["rebootRequired"] == true,
      ipv4: list(doc["ipv4Addrs"]),
      ipv6: list(doc["ipv6Addrs"]),
      platform: blank(get_in(doc, ["platform", "name"])),
      scan_mode: blank(doc["scanMode"]),
      scanned_via: blank(doc["scannedVia"]),
      scanned_by: blank(doc["scannedBy"]),
      scanned_version: blank(doc["scannedVersion"]),
      reported_version: blank(doc["reportedVersion"]),
      scanned_at: time(doc["scannedAt"]),
      reported_at: time(doc["reportedAt"]),
      errors: list(doc["errors"]),
      warnings: list(doc["warnings"]),
      counts: counts(vulns),
      packages_count: map_size(packages),
      upgradable_count: Enum.count(pkg_rows, & &1.new_version),
      libraries_count:
        doc["libraries"] |> List.wrap() |> Enum.map(&length(list(&1["Libs"]))) |> Enum.sum(),
      vulns: vulns,
      packages: pkg_rows
    }
  end

  @doc "Builds a placeholder scan for a file that could not be parsed."
  @spec failed(map(), String.t()) :: Scan.t()
  def failed(file, reason) do
    %Scan{
      id: file.id,
      host: file.host,
      dir: file.dir,
      path: file.path,
      mtime: file.mtime,
      size: file.size,
      scanned_at: dir_time(file.dir),
      parse_error: reason,
      vulns: [],
      packages: []
    }
  end

  @doc "Severity / fix / exploit counts for a list of vulns."
  @spec counts([Vuln.t()]) :: Scan.counts()
  def counts(vulns) do
    base = %{
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
      total: 0,
      fixable: 0,
      unfixed: 0,
      kev: 0,
      exploitable: 0
    }

    Enum.reduce(vulns, base, fn v, acc ->
      acc
      |> Map.update!(v.severity, &(&1 + 1))
      |> Map.update!(:total, &(&1 + 1))
      |> bump(:fixable, v.fix_status == :fixable)
      |> bump(:unfixed, v.fix_status == :unfixed)
      |> bump(:kev, v.kev)
      |> bump(:exploitable, v.exploits + v.metasploits > 0)
    end)
  end

  @doc """
  Parses the timestamp encoded in a results directory name. vuls >= v0.23
  uses `2006-01-02T15-04-05-0700`, older releases RFC 3339
  (`2006-01-02T15:04:05+07:00` / `...Z`).
  """
  @spec dir_time(String.t()) :: DateTime.t() | nil
  def dir_time(dir) do
    iso =
      case Regex.run(~r/^(\d{4}-\d\d-\d\d)T(\d\d)-(\d\d)-(\d\d)([+-]\d\d)(\d\d)$/, dir) do
        [_, date, h, mi, s, oh, om] -> "#{date}T#{h}:#{mi}:#{s}#{oh}:#{om}"
        nil -> dir
      end

    case DateTime.from_iso8601(iso) do
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  # -- vulns ------------------------------------------------------------------

  defp vuln(cve_id, vuln, packages, family) do
    max = Scoring.max_score(vuln)

    %Vuln{
      cve_id: blank(vuln["cveID"]) || cve_id,
      score: max && max.score,
      severity: severity_bucket(vuln),
      cvss_version: max && max.version,
      cvss_type: max && max.type,
      cvss_vector: max && max.vector,
      summary: summary(vuln, family),
      affected: affected(vuln, packages),
      fix_status: fix_status(vuln, packages),
      kev: kev?(vuln),
      exploits: length(list(vuln["exploits"])),
      metasploits: length(list(vuln["metasploits"])),
      attack_vector: Scoring.attack_vector(vuln),
      confidence: confidence(vuln),
      published: published(vuln),
      cwe_ids: cwe_ids(vuln),
      diff_status: blank(vuln["diffStatus"])
    }
  end

  # Same cascade as vuls' CountGroupBySeverity.
  defp severity_bucket(vuln) do
    score =
      Enum.find_value(
        [&Scoring.cvss40_scores/1, &Scoring.cvss3_scores/1, &Scoring.cvss2_scores/1],
        0.0,
        fn fun ->
          max = vuln |> fun.() |> Enum.map(& &1.score) |> Enum.max(fn -> 0.0 end)
          if max >= 0.1, do: max
        end
      )

    Scoring.severity(score)
  end

  @doc false
  # Port of vuls' VulnInfo.PatchStatus: "fixed" there means a fix is available.
  def fix_status(vuln, packages) do
    confidences = list(vuln["confidences"]) |> Enum.map(& &1["detectionMethod"])
    affected = list(vuln["affectedPackages"])

    cond do
      "WindowsRoughMatch" in confidences ->
        :unknown

      "WindowsUpdateSearch" in confidences ->
        cond do
          Enum.any?(affected, &(&1["fixState"] == "unknown")) ->
            :unknown

          Enum.any?(affected, &(&1["fixState"] == "unfixed")) or
              (affected == [] and list(vuln["windowsKBFixedIns"]) == []) ->
            :unfixed

          true ->
            :fixable
        end

      list(vuln["cpeURIs"]) != [] ->
        :unknown

      true ->
        Enum.reduce_while(affected, :fixable, fn p, acc ->
          cond do
            p["notFixedYet"] == true ->
              {:halt, :unfixed}

            present?(p["fixedIn"]) ->
              {:cont, acc}

            match?(%{}, packages[p["name"]]) and not present?(packages[p["name"]]["newVersion"]) ->
              {:halt, :unknown}

            true ->
              {:cont, acc}
          end
        end)
    end
  end

  defp affected(vuln, packages) do
    pkgs =
      for p <- list(vuln["affectedPackages"]) do
        pack = map(packages[p["name"]])

        %{
          kind: :package,
          name: p["name"],
          version: version(pack["version"], pack["release"]),
          new_version: version(pack["newVersion"], pack["newRelease"]),
          fixed_in: blank(p["fixedIn"]),
          fix_state: blank(p["fixState"]),
          not_fixed_yet: p["notFixedYet"] == true,
          path: nil
        }
      end

    libs =
      for l <- list(vuln["libraryFixedIns"]) do
        %{
          kind: :library,
          name: l["name"],
          version: blank(l["version"]),
          new_version: nil,
          fixed_in: blank(l["fixedIn"]),
          fix_state: nil,
          not_fixed_yet: not present?(l["fixedIn"]),
          path: blank(l["path"])
        }
      end

    cpes =
      for uri <- list(vuln["cpeURIs"]) do
        %{
          kind: :cpe,
          name: uri,
          version: nil,
          new_version: nil,
          fixed_in: nil,
          fix_state: nil,
          not_fixed_yet: false,
          path: nil
        }
      end

    wp =
      for w <- list(vuln["wpPackageFixStats"]) do
        %{
          kind: :wordpress,
          name: w["name"],
          version: nil,
          new_version: nil,
          fixed_in: blank(w["fixedIn"]),
          fix_state: nil,
          not_fixed_yet: not present?(w["fixedIn"]),
          path: nil
        }
      end

    gh =
      for a <- list(vuln["gitHubSecurityAlerts"]) do
        %{
          kind: :github,
          name: get_in(a, ["package", "name"]) || a["repository"],
          version: blank(get_in(a, ["package", "requirements"])),
          new_version: nil,
          fixed_in: blank(a["fixedIn"]),
          fix_state: if(a["dismissed"], do: "dismissed"),
          not_fixed_yet: not present?(a["fixedIn"]),
          path: blank(get_in(a, ["package", "manifestPath"]))
        }
      end

    kbs =
      for kb <- list(vuln["windowsKBFixedIns"]) do
        %{
          kind: :windows_kb,
          name: "KB#{kb}",
          version: nil,
          new_version: nil,
          fixed_in: "KB#{kb}",
          fix_state: nil,
          not_fixed_yet: false,
          path: nil
        }
      end

    pkgs ++ libs ++ cpes ++ wp ++ gh ++ kbs
  end

  defp kev?(vuln) do
    list(vuln["kevs"]) != [] or list(get_in(map(vuln["alertDict"]), ["cisa"])) != []
  end

  defp confidence(vuln) do
    vuln["confidences"]
    |> list()
    |> Enum.max_by(&(&1["score"] || 0), fn -> nil end)
    |> case do
      nil -> nil
      c -> c["detectionMethod"]
    end
  end

  defp cwe_ids(vuln) do
    vuln["cveContents"]
    |> map()
    |> Map.values()
    |> List.flatten()
    |> Enum.flat_map(&list(&1["cweIDs"]))
    |> Enum.uniq()
    |> Enum.sort()
  end

  defp published(vuln) do
    vuln["cveContents"]
    |> map()
    |> Map.values()
    |> List.flatten()
    |> Enum.map(&time(&1["published"]))
    |> Enum.reject(&is_nil/1)
    |> Enum.min(DateTime, fn -> nil end)
    |> case do
      nil -> nil
      dt -> DateTime.to_date(dt)
    end
  end

  # Same order as vuls' VulnInfo.Summaries (English).
  @trivy_first ~w(trivy)
  @tail_order ~w(cisco paloalto fortinet euvd nvd vulncheck mitre github)

  defp summary(vuln, family) do
    contents = map(vuln["cveContents"])
    keys = Map.keys(contents)
    trivy = keys |> Enum.filter(&String.starts_with?(&1, @trivy_first)) |> Enum.sort()
    order = trivy ++ family_types(family) ++ @tail_order
    order = order ++ ((keys -- order) -- ["jvn"])

    from_contents =
      Enum.find_value(order, fn type ->
        contents
        |> Map.get(type)
        |> list()
        |> Enum.find_value(fn c -> blank(c["summary"]) end)
      end)

    text =
      from_contents ||
        Enum.find_value(list(vuln["distroAdvisories"]), &blank(&1["description"])) ||
        Enum.find_value(list(contents["wpscan"]), &blank(&1["title"]))

    text && text |> String.replace(~r/\s+/, " ") |> String.trim() |> truncate(@summary_limit)
  end

  @doc false
  def family_types(family) do
    case family do
      f when f in ["redhat", "centos"] ->
        ["redhat", "redhat_api"]

      "alma" ->
        ["alma"]

      "rocky" ->
        ["rocky"]

      "fedora" ->
        ["fedora"]

      "oracle" ->
        ["oracle"]

      "amazon" ->
        ["amazon"]

      f when f in ["debian", "raspbian"] ->
        ["debian", "debian_security_tracker"]

      "ubuntu" ->
        ["ubuntu", "ubuntu_api"]

      "alpine" ->
        ["alpine"]

      "windows" ->
        ["microsoft"]

      f when is_binary(f) ->
        cond do
          String.contains?(f, "suse") -> ["suse"]
          String.starts_with?(f, "mac") -> ["apple"]
          true -> []
        end

      _ ->
        []
    end
  end

  # -- packages ---------------------------------------------------------------

  defp package_rows(packages, vulns) do
    vuln_counts =
      vulns
      |> Enum.flat_map(fn v ->
        v.affected |> Enum.filter(&(&1.kind == :package)) |> Enum.map(& &1.name) |> Enum.uniq()
      end)
      |> Enum.frequencies()

    packages
    |> Enum.map(fn {name, p} ->
      p = map(p)

      %{
        name: blank(p["name"]) || name,
        version: version(p["version"], p["release"]) || "",
        new_version: version(p["newVersion"], p["newRelease"]),
        arch: blank(p["arch"]),
        repository: blank(p["repository"]),
        vulns: Map.get(vuln_counts, name, 0)
      }
    end)
    |> Enum.sort_by(& &1.name)
  end

  # -- helpers ----------------------------------------------------------------

  defp version(v, r) do
    case {blank(v), blank(r)} do
      {nil, _} -> nil
      {v, nil} -> v
      {v, r} -> "#{v}-#{r}"
    end
  end

  defp bump(acc, key, true), do: Map.update!(acc, key, &(&1 + 1))
  defp bump(acc, _key, _), do: acc

  defp time(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      # Go's zero time ("0001-01-01T00:00:00Z") means "unset".
      {:ok, %DateTime{year: 1}, _} -> nil
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp time(_), do: nil

  defp truncate(s, n) do
    if String.length(s) > n, do: String.slice(s, 0, n - 1) <> "…", else: s
  end

  defp map(m) when is_map(m), do: m
  defp map(_), do: %{}

  defp list(l) when is_list(l), do: l
  defp list(_), do: []

  defp blank(s) when is_binary(s) do
    case String.trim(s) do
      "" -> nil
      _ -> s
    end
  end

  defp blank(_), do: nil

  defp present?(s), do: blank(s) != nil
end
