defmodule Vulsweb.Vuls.ReportTest do
  use ExUnit.Case, async: true

  alias Vulsweb.Vuls.Report

  @file_info %{id: "d/h.json", host: "h", dir: "d", path: "/x/d/h.json", mtime: 0, size: 0}

  describe "fix_status/2 (vuls PatchStatus)" do
    test "not fixed yet wins" do
      v = %{
        "affectedPackages" => [
          %{"name" => "a", "fixedIn" => "1"},
          %{"name" => "b", "notFixedYet" => true}
        ]
      }

      assert Report.fix_status(v, %{}) == :unfixed
    end

    test "fixable when fixedIn is known or a candidate version exists" do
      assert Report.fix_status(
               %{"affectedPackages" => [%{"name" => "a", "fixedIn" => "1.2"}]},
               %{}
             ) ==
               :fixable

      packs = %{"a" => %{"newVersion" => "2.0"}}
      assert Report.fix_status(%{"affectedPackages" => [%{"name" => "a"}]}, packs) == :fixable
    end

    test "unknown without a candidate version (fast/offline scans)" do
      packs = %{"a" => %{"newVersion" => ""}}
      assert Report.fix_status(%{"affectedPackages" => [%{"name" => "a"}]}, packs) == :unknown
    end

    test "CPE matches are unknown" do
      assert Report.fix_status(%{"cpeURIs" => ["cpe:/a:x:y"]}, %{}) == :unknown
    end

    test "windows update search" do
      v = %{
        "confidences" => [%{"detectionMethod" => "WindowsUpdateSearch"}],
        "windowsKBFixedIns" => ["5034441"]
      }

      assert Report.fix_status(v, %{}) == :fixable

      v = %{"confidences" => [%{"detectionMethod" => "WindowsUpdateSearch"}]}
      assert Report.fix_status(v, %{}) == :unfixed
    end
  end

  test "summarize builds counts, rows and package info" do
    doc = %{
      "serverName" => "h",
      "family" => "ubuntu",
      "release" => "24.04",
      "scannedAt" => "2026-11-21T10:00:00+03:00",
      "runningKernel" => %{"release" => "6.8", "rebootRequired" => true},
      "packages" => %{
        "openssl" => %{
          "name" => "openssl",
          "version" => "3.0",
          "release" => "1",
          "newVersion" => "3.1",
          "newRelease" => "1"
        },
        "bash" => %{"name" => "bash", "version" => "5.2"}
      },
      "scannedCves" => %{
        "CVE-1" => %{
          "affectedPackages" => [%{"name" => "openssl"}],
          "cveContents" => %{"nvd" => [%{"cvss3Score" => 9.8, "summary" => "boom\nline"}]},
          "kevs" => [%{"type" => "cisa"}]
        },
        "CVE-2" => %{
          "affectedPackages" => [%{"name" => "openssl", "notFixedYet" => true}],
          "cveContents" => %{"ubuntu" => [%{"cvss3Severity" => "medium"}]},
          "exploits" => [%{"url" => "x"}]
        }
      }
    }

    scan = Report.summarize(doc, @file_info)

    assert scan.reboot_required

    assert scan.counts == %{
             critical: 1,
             high: 0,
             medium: 1,
             low: 0,
             unknown: 0,
             total: 2,
             fixable: 1,
             unfixed: 1,
             kev: 1,
             exploitable: 1
           }

    assert [%{cve_id: "CVE-1", severity: :critical, summary: "boom line", kev: true} = v1, v2] =
             scan.vulns

    assert [%{name: "openssl", version: "3.0-1", new_version: "3.1-1"}] = v1.affected
    assert v2.fix_status == :unfixed
    assert scan.packages_count == 2
    assert scan.upgradable_count == 1
    assert Enum.find(scan.packages, &(&1.name == "openssl")).vulns == 2
  end

  test "go zero times are treated as unset" do
    scan = Report.summarize(%{"scannedAt" => "0001-01-01T00:00:00Z"}, @file_info)
    assert scan.scanned_at == nil
  end

  test "dir_time parses vuls result directory names" do
    assert Report.dir_time("2026-11-21T10-15-00+0300") == ~U[2026-11-21 07:15:00Z]
    assert Report.dir_time("current") == nil
  end
end
