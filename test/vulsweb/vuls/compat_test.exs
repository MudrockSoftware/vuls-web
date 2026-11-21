defmodule Vulsweb.Vuls.CompatTest do
  use ExUnit.Case, async: true

  alias Vulsweb.Vuls.{Compat, Report}

  @file_info %{id: "d/h.json", host: "h", dir: "d", path: "/x", mtime: 0, size: 0}

  # The layout vuls v0.13 - v0.15.13 wrote: single-object cveContents,
  # alertDict {en, ja}, libScanners, GitHub alerts with packageName.
  defp legacy_v4 do
    %{
      "jsonVersion" => 4,
      "serverName" => "old01",
      "family" => "centos",
      "release" => "7.9.2009",
      "scannedAt" => "2021-06-01T10:00:00+09:00",
      "packages" => %{
        "openssl" => %{"name" => "openssl", "version" => "1.0.2k", "newVersion" => "1.0.2k-22"}
      },
      "libScanners" => [
        %{"path" => "/app/Gemfile.lock", "Libs" => [%{"Name" => "rails", "Version" => "6.0"}]}
      ],
      "scannedCves" => %{
        "CVE-2021-3449" => %{
          "cveID" => "CVE-2021-3449",
          "affectedPackages" => [%{"name" => "openssl"}],
          "cveContents" => %{
            "nvd" => %{
              "type" => "nvd",
              "summary" => "NULL pointer deref",
              "cvss3Score" => 5.9,
              "cweIDs" => ["CWE-476"]
            },
            "redhat" => %{"type" => "redhat", "cvss3Score" => 5.9, "cvss3Severity" => "Important"}
          },
          "alertDict" => %{
            "en" => [%{"title" => "US-CERT alert", "url" => "https://us-cert"}],
            "ja" => []
          },
          "gitHubSecurityAlerts" => [
            %{"packageName" => "rails", "fixedIn" => "6.1", "repository" => "acme/app"}
          ]
        }
      }
    }
  end

  test "normalizes pre-v0.15.14 / pre-v0.19 layouts" do
    {:ok, doc} = Compat.normalize(legacy_v4())
    vuln = doc["scannedCves"]["CVE-2021-3449"]

    assert [%{"summary" => "NULL pointer deref"}] = vuln["cveContents"]["nvd"]
    assert %{"uscert" => [%{"title" => "US-CERT alert"}], "jpcert" => []} = vuln["alertDict"]
    refute Map.has_key?(vuln["alertDict"], "en")
    assert [%{"package" => %{"name" => "rails"}}] = vuln["gitHubSecurityAlerts"]
    assert [%{"path" => "/app/Gemfile.lock"}] = doc["libraries"]
  end

  test "legacy documents summarize like current ones" do
    {:ok, doc} = Compat.normalize(legacy_v4())
    scan = Report.summarize(doc, @file_info)

    assert [vuln] = scan.vulns
    assert vuln.summary == "NULL pointer deref"
    # Red Hat content carries a real CVSS score (5.9), so its "Important"
    # label is not converted to a rough score, same as vuls.
    assert vuln.severity == :medium
    assert vuln.score == 5.9
    assert vuln.cwe_ids == ["CWE-476"]
    assert Enum.any?(vuln.affected, &(&1.kind == :github and &1.name == "rails"))
    assert scan.libraries_count == 1
  end

  test "current documents pass through unchanged" do
    doc = %{
      "jsonVersion" => 4,
      "scannedCves" => %{"CVE-1" => %{"cveContents" => %{"nvd" => [%{"cvss3Score" => 9.8}]}}},
      "libraries" => []
    }

    assert Compat.normalize(doc) == {:ok, doc}
  end

  test "rejects result files from vuls before v0.5.0" do
    assert {:error, "unsupported result format (jsonVersion 3" <> _} =
             Compat.normalize(%{"jsonVersion" => 3, "scannedCves" => %{}})

    assert {:error, "unsupported result format" <> _} =
             Compat.normalize(%{"ScannedCves" => [], "KnownCves" => []})

    assert {:error, "not a vuls result" <> _} = Compat.normalize([1, 2])
  end

  test "read_file reports unreadable and invalid files" do
    assert {:error, "cannot read file: " <> _} = Compat.read_file("/nonexistent/x.json")

    path =
      Path.join(System.tmp_dir!(), "vulsweb-compat-#{System.unique_integer([:positive])}.json")

    File.write!(path, "{nope")
    on_exit(fn -> File.rm(path) end)
    assert {:error, "invalid JSON: " <> _} = Compat.read_file(path)
  end

  test "dir_time understands every result dir layout vuls used" do
    # vuls >= v0.23
    assert Report.dir_time("2026-11-21T10-15-00+0300") == ~U[2026-11-21 07:15:00Z]
    # vuls < v0.23 (RFC 3339)
    assert Report.dir_time("2021-06-01T10:00:00+09:00") == ~U[2021-06-01 01:00:00Z]
    assert Report.dir_time("2021-06-01T10:00:00Z") == ~U[2021-06-01 10:00:00Z]
    assert Report.dir_time("current") == nil
  end
end
