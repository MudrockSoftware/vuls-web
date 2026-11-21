defmodule Vulsweb.Vuls.Scoring do
  @moduledoc """
  CVSS scoring helpers ported from vuls `models/vulninfos.go` so that the
  numbers shown here match `vuls report` / `vuls tui`.

  Every function works on a decoded `scannedCves` entry (a plain map with
  string keys, as produced by `Jason.decode/1`).
  """

  @severities [:critical, :high, :medium, :low, :unknown]

  @type severity :: :critical | :high | :medium | :low | :unknown

  @doc "All severity buckets, most severe first."
  def severities, do: @severities

  # Source order is significant: on equal scores the first source wins.
  @v2_order ~w(redhat_api redhat solaris nvd vulncheck mitre jvn euvd)
  @v3_order ~w(redhat_api redhat rocky suse microsoft paloalto fortinet solaris nvd vulncheck mitre jvn euvd)
  @v3_severity_only ~w(debian debian_security_tracker ubuntu ubuntu_api amazon github wpscan)
  @v40_order ~w(paloalto mitre nvd vulncheck euvd)

  @type cvss :: %{
          type: String.t(),
          source: String.t() | nil,
          version: String.t(),
          score: float(),
          vector: String.t() | nil,
          severity: String.t() | nil,
          calculated_by_severity: boolean()
        }

  @doc "CVSS v2 scores from every source, in vuls priority order."
  @spec cvss2_scores(map()) :: [cvss()]
  def cvss2_scores(vuln) do
    contents = contents(vuln)

    for type <- @v2_order ++ trivy_types(contents),
        cont <- Map.get(contents, type, []),
        num(cont["cvss2Score"]) != 0 or present?(cont["cvss2Severity"]) do
      score(type, cont, "2", cont["cvss2Score"], cont["cvss2Vector"], cont["cvss2Severity"])
    end
  end

  @doc "CVSS v3 scores (including severity-only sources and distro advisories)."
  @spec cvss3_scores(map()) :: [cvss()]
  def cvss3_scores(vuln) do
    contents = contents(vuln)
    trivy = trivy_types(contents)

    scored =
      for type <- @v3_order ++ trivy,
          cont <- Map.get(contents, type, []),
          num(cont["cvss3Score"]) != 0 or present?(cont["cvss3Severity"]) do
        score(type, cont, "3", cont["cvss3Score"], cont["cvss3Vector"], cont["cvss3Severity"])
      end

    severity_only =
      for type <- @v3_severity_only ++ trivy,
          cont <- Map.get(contents, type, []),
          present?(cont["cvss3Severity"]) do
        severity = cont["cvss3Severity"]

        # The Debian security tracker may list several severities ("low|medium"),
        # sorted ascending; the largest one is used.
        rough =
          if type == "debian_security_tracker",
            do: severity |> String.split("|") |> List.last(),
            else: severity

        %{
          type: type,
          source: nil,
          version: "3",
          score: rough_score(rough),
          vector: nil,
          severity: String.upcase(severity),
          calculated_by_severity: true
        }
      end

    advisories =
      for adv <- List.wrap(vuln["distroAdvisories"]), present?(adv["severity"]) do
        %{
          type: "vendor",
          source: adv["advisoryID"],
          version: "3",
          score: rough_score(adv["severity"]),
          vector: nil,
          severity: String.upcase(adv["severity"]),
          calculated_by_severity: true
        }
      end

    scored ++ severity_only ++ advisories
  end

  @doc "CVSS v4.0 scores from every source."
  @spec cvss40_scores(map()) :: [cvss()]
  def cvss40_scores(vuln) do
    contents = contents(vuln)

    for type <- @v40_order,
        cont <- Map.get(contents, type, []),
        num(cont["cvss40Score"]) != 0 or present?(cont["cvss40Severity"]) do
      score(type, cont, "4.0", cont["cvss40Score"], cont["cvss40Vector"], cont["cvss40Severity"])
    end
  end

  @doc "All scores, newest CVSS version first."
  @spec all_scores(map()) :: [cvss()]
  def all_scores(vuln), do: cvss40_scores(vuln) ++ cvss3_scores(vuln) ++ cvss2_scores(vuln)

  @doc """
  The headline score, like vuls' `MaxCvssScore`: the max v4.0 score if any,
  else the max v3, else the max v2. Returns `nil` if nothing is scored.
  """
  @spec max_score(map()) :: cvss() | nil
  def max_score(vuln) do
    max_of(cvss40_scores(vuln)) || max_of(cvss3_scores(vuln)) || max_of(cvss2_scores(vuln))
  end

  @doc "Severity bucket from a score, like vuls' `CountGroupBySeverity`."
  @spec severity(number() | nil) :: severity()
  def severity(nil), do: :unknown
  def severity(score) when score >= 9.0, do: :critical
  def severity(score) when score >= 7.0, do: :high
  def severity(score) when score >= 4.0, do: :medium
  def severity(score) when score > 0, do: :low
  def severity(_), do: :unknown

  @doc "Attack vector (AV:N / AV:A / AV:L / AV:P), like vuls' `AttackVector`."
  @spec attack_vector(map()) :: String.t() | nil
  def attack_vector(vuln) do
    contents = contents(vuln)
    conts = contents |> Map.values() |> List.flatten()

    Enum.find_value(conts, fn cont ->
      v2 = cont["cvss2Vector"] || ""
      v3 = cont["cvss3Vector"] || ""
      v4 = cont["cvss40Vector"] || ""

      cond do
        String.starts_with?(v2, "AV:N") or String.contains?(v3, "AV:N") or
            String.contains?(v4, "AV:N") ->
          "AV:N"

        String.starts_with?(v2, "AV:A") or String.contains?(v3, "AV:A") or
            String.contains?(v4, "AV:A") ->
          "AV:A"

        String.starts_with?(v2, "AV:L") or String.contains?(v3, "AV:L") or
            String.contains?(v4, "AV:L") ->
          "AV:L"

        String.contains?(v3, "AV:P") or String.contains?(v4, "AV:P") ->
          "AV:P"

        true ->
          nil
      end
    end) ||
      Enum.find_value(Map.get(contents, "debian_security_tracker", []), fn cont ->
        get_in(cont, ["optional", "attack range"])
      end)
  end

  @doc "Human label for an attack vector code."
  def attack_vector_label("AV:N"), do: "Network"
  def attack_vector_label("AV:A"), do: "Adjacent"
  def attack_vector_label("AV:L"), do: "Local"
  def attack_vector_label("AV:P"), do: "Physical"
  def attack_vector_label(nil), do: nil
  def attack_vector_label(other), do: other

  @doc "Rough CVSS score for a qualitative severity (vuls' `severityToCvssScoreRoughly`)."
  def rough_score(severity) when is_binary(severity) do
    case String.upcase(severity) do
      "CRITICAL" -> 10.0
      s when s in ["IMPORTANT", "HIGH"] -> 8.9
      s when s in ["MODERATE", "MEDIUM"] -> 6.9
      s when s in ["LOW", "NEGLIGIBLE"] -> 3.9
      _ -> 0.0
    end
  end

  def rough_score(_), do: 0.0

  defp max_of(scores) do
    # vuls starts from score 0 and only replaces on a strictly greater score,
    # so a list of zero scores yields "unknown".
    Enum.reduce(scores, nil, fn s, acc ->
      if s.score > ((acc && acc.score) || 0), do: s, else: acc
    end)
  end

  defp score(type, cont, version, score, vector, severity) do
    %{
      type: type,
      source: get_in(cont, ["optional", "source"]),
      version: version,
      score: num(score),
      vector: blank_to_nil(vector),
      severity: severity |> blank_to_nil() |> upcase(),
      calculated_by_severity: false
    }
  end

  defp contents(vuln) do
    case vuln["cveContents"] do
      m when is_map(m) -> Map.new(m, fn {k, v} -> {k, List.wrap(v)} end)
      _ -> %{}
    end
  end

  defp trivy_types(contents) do
    contents |> Map.keys() |> Enum.filter(&String.starts_with?(&1, "trivy")) |> Enum.sort()
  end

  defp num(n) when is_number(n), do: n / 1
  defp num(_), do: 0.0

  defp present?(s), do: is_binary(s) and s != ""

  defp blank_to_nil(""), do: nil
  defp blank_to_nil(s), do: s

  defp upcase(nil), do: nil
  defp upcase(s), do: String.upcase(s)
end
