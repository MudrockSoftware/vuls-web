defmodule Vulsweb.Vuls.ScoringTest do
  use ExUnit.Case, async: true

  alias Vulsweb.Vuls.Scoring

  defp vuln(contents, extra \\ %{}), do: Map.merge(%{"cveContents" => contents}, extra)

  test "prefers the max CVSS v4.0 score over v3 and v2" do
    v =
      vuln(%{
        "nvd" => [%{"cvss40Score" => 8.7, "cvss3Score" => 9.8, "cvss2Score" => 10.0}],
        "mitre" => [%{"cvss40Score" => 9.3}]
      })

    assert %{version: "4.0", score: 9.3, type: "mitre"} = Scoring.max_score(v)
  end

  test "falls back to v3, then v2" do
    assert %{version: "3", score: 7.5} =
             Scoring.max_score(vuln(%{"nvd" => [%{"cvss3Score" => 7.5, "cvss2Score" => 9.0}]}))

    assert %{version: "2", score: 5.0} =
             Scoring.max_score(vuln(%{"nvd" => [%{"cvss2Score" => 5.0}]}))

    assert Scoring.max_score(vuln(%{})) == nil
  end

  test "severity-only sources get vuls' rough scores" do
    v = vuln(%{"ubuntu" => [%{"cvss3Severity" => "high"}]})
    assert %{score: 8.9, calculated_by_severity: true, severity: "HIGH"} = Scoring.max_score(v)

    # Debian security tracker lists sorted severities, the largest wins.
    v = vuln(%{"debian_security_tracker" => [%{"cvss3Severity" => "low|medium"}]})
    assert %{score: 6.9, severity: "LOW|MEDIUM"} = Scoring.max_score(v)
  end

  test "distro advisories count as vendor v3 scores" do
    v =
      vuln(%{}, %{"distroAdvisories" => [%{"advisoryID" => "RHSA-1", "severity" => "Critical"}]})

    assert %{type: "vendor", score: 10.0, source: "RHSA-1"} = Scoring.max_score(v)
  end

  test "severity buckets match vuls' CountGroupBySeverity" do
    assert Scoring.severity(9.0) == :critical
    assert Scoring.severity(8.9) == :high
    assert Scoring.severity(7.0) == :high
    assert Scoring.severity(4.0) == :medium
    assert Scoring.severity(0.1) == :low
    assert Scoring.severity(0.0) == :unknown
    assert Scoring.severity(nil) == :unknown
  end

  test "attack vector from any vector string" do
    assert Scoring.attack_vector(vuln(%{"nvd" => [%{"cvss3Vector" => "CVSS:3.1/AV:N/AC:L"}]})) ==
             "AV:N"

    assert Scoring.attack_vector(vuln(%{"nvd" => [%{"cvss2Vector" => "AV:L/AC:L"}]})) == "AV:L"
    assert Scoring.attack_vector(vuln(%{})) == nil
  end
end
