defmodule Vulsweb.Results.StoreTest do
  use Vulsweb.ResultsCase, async: false

  alias Vulsweb.Results

  test "indexes the newest scan of every host across result dirs" do
    hosts = Results.hosts()
    assert Enum.map(hosts, & &1.host) == ~w(db01 mon01 redis@docker01 web01 web02)
    # The light summaries carry no CVE rows.
    assert Enum.all?(hosts, &(&1.vulns == nil))

    web01 = Results.host("web01")
    assert length(web01.vulns) == web01.counts.total
    assert [latest | _] = Results.history("web01")
    assert latest.id == web01.id
    assert length(Results.history("web01")) == 3
    assert Results.status().state == :ready
  end

  test "aggregates CVEs across hosts" do
    row = Enum.find(Results.cves(), &(&1.cve_id == "CVE-2024-6387"))
    assert row.kev
    assert "web01" in row.hosts

    assert {:ok, %{detail: detail, hosts: affected}} = Results.cve("CVE-2024-6387")
    assert detail.max.version == "4.0"
    assert detail.kevs != []
    assert length(affected) == length(row.hosts)
    assert Results.cve("CVE-1999-0001") == {:error, :not_found}
  end

  test "picks up new results and broadcasts", %{results_dir: dir} do
    Results.subscribe()
    at = DateTime.add(DateTime.utc_now(), -10, :second) |> DateTime.truncate(:second)
    write_result(dir, "new01", at, minimal_result("new01", at, [{"CVE-2026-0001", 9.8}]))

    :ok = Results.refresh()

    assert_receive {:results_updated, ["new01"]}
    assert %{counts: %{critical: 1, total: 1}} = Results.host("new01")
  end

  test "a newer scan replaces the latest and diffs against the previous", %{results_dir: dir} do
    old = Results.host("web02")
    at = DateTime.add(DateTime.utc_now(), -5, :second) |> DateTime.truncate(:second)
    write_result(dir, "web02", at, minimal_result("web02", at, [{"CVE-2026-0002", 5.0}]))
    :ok = Results.refresh()

    new = Results.host("web02")
    assert new.id != old.id
    assert new.counts.total == 1

    diff = Results.diff(new)
    assert Enum.map(diff.added, & &1.cve_id) == ["CVE-2026-0002"]
    assert length(diff.resolved) == old.counts.total
  end

  test "a broken newest file does not hide the last good scan", %{results_dir: dir} do
    good = Results.host("db01")
    at = DateTime.add(DateTime.utc_now(), -5, :second) |> DateTime.truncate(:second)
    sub = Path.join(dir, Vulsweb.Sample.dirname(at))
    File.mkdir_p!(sub)
    File.write!(Path.join(sub, "db01.json"), ~s({"scannedCves": {"CVE-))
    :ok = Results.refresh()

    assert Results.host("db01").id == good.id
    assert [%{parse_error: "invalid JSON" <> _} | _] = Results.history("db01")
    assert Results.status().failed == 1
  end

  test "removed files drop out of the index", %{results_dir: dir} do
    for path <- Path.wildcard(Path.join(dir, "*/mon01.json")), do: File.rm!(path)
    :ok = Results.refresh()
    assert Results.host("mon01") == nil
    refute Enum.any?(Results.hosts(), &(&1.host == "mon01"))
  end

  test "skips symlinked dirs and _diff.json files", %{results_dir: dir} do
    [first | _] = File.ls!(dir) |> Enum.sort()
    File.ln_s!(Path.join(dir, first), Path.join(dir, "current"))
    File.write!(Path.join([dir, first, "web01_diff.json"]), "{}")

    before = Results.status().files
    :ok = Results.refresh()
    assert Results.status().files == before
    refute Enum.any?(Results.hosts(), &(&1.host == "web01_diff"))
  end

  test "reports a missing results directory" do
    assert {:error, "directory does not exist"} =
             Vulsweb.Results.Store.list_files("/nonexistent/vulsweb")
  end

  test "explains unreadable result directories (vuls writes them 0700)", %{results_dir: dir} do
    if System.get_env("USER") == "root" or File.stat!(dir).uid == 0 do
      :ok
    else
      dirs = dir |> File.ls!() |> Enum.map(&Path.join(dir, &1))
      Enum.each(dirs, &File.chmod!(&1, 0o000))
      on_exit(fn -> Enum.each(dirs, &File.chmod(&1, 0o700)) end)

      assert {:error, "permission denied reading " <> _} = Vulsweb.Results.Store.list_files(dir)
      ExUnit.CaptureLog.capture_log(fn -> :ok = Results.refresh() end)
      assert %{state: :error, error: "permission denied" <> _} = Results.status()
    end
  end

  test "indexes old result files (RFC 3339 dirs, pre-v0.15.14 layout)", %{results_dir: dir} do
    sub = Path.join(dir, "2021-06-01T10:00:00+09:00")
    File.mkdir_p!(sub)

    doc = %{
      "jsonVersion" => 4,
      "serverName" => "old01",
      "family" => "centos",
      "release" => "7",
      "scannedAt" => "2021-06-01T10:00:00+09:00",
      "scannedCves" => %{
        "CVE-2021-3449" => %{
          "cveContents" => %{"nvd" => %{"summary" => "old layout", "cvss3Score" => 7.5}},
          "alertDict" => %{"en" => [], "ja" => []}
        }
      }
    }

    path = Path.join(sub, "old01.json")
    File.write!(path, Jason.encode!(doc))
    File.touch!(path, 1_622_509_200)
    File.write!(Path.join(sub, "ancient.json"), ~s({"jsonVersion": 3, "scannedCves": {}}))
    File.touch!(Path.join(sub, "ancient.json"), 1_622_509_200)
    :ok = Results.refresh()

    assert %{counts: %{high: 1, total: 1}, vulns: [%{summary: "old layout"}]} =
             Results.host("old01")

    assert {:ok, %{detail: %{summary: "old layout"}}} = Results.cve("CVE-2021-3449")

    assert %{parse_error: "unsupported result format (jsonVersion 3" <> _} =
             Results.host("ancient")
  end
end
