defmodule VulswebWeb.PagesTest do
  use VulswebWeb.ConnCase, async: false
  use Vulsweb.ResultsCase

  import Phoenix.LiveViewTest

  test "dashboard lists hosts and totals", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/")
    assert html =~ "Fleet overview"
    assert has_element?(view, "#host-web01")
    assert has_element?(view, "#host-redis\\@docker01")
    assert has_element?(view, "#top-CVE-2024-6387")

    html = view |> form("#host-search", q: "db0") |> render_change()
    assert html =~ "db01"
    refute has_element?(view, "#host-web01")
  end

  test "dashboard updates live when a new result arrives", %{conn: conn, results_dir: dir} do
    {:ok, view, _html} = live(conn, ~p"/")
    refute has_element?(view, "#host-live01")

    at = DateTime.add(DateTime.utc_now(), -5, :second) |> DateTime.truncate(:second)
    write_result(dir, "live01", at, minimal_result("live01", at, [{"CVE-2026-1111", 7.5}]))
    :ok = Vulsweb.Results.refresh()

    assert render(view) =~ "live01"
    assert has_element?(view, "#host-live01")
  end

  test "host page filters vulnerabilities", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/hosts/web01")
    assert html =~ "Reboot required"
    assert has_element?(view, "#vuln-CVE-2024-6387")

    view |> form("#vuln-filters", q: "regreSSHion") |> render_change()
    assert_patch(view)
    assert has_element?(view, "#vuln-CVE-2024-6387")
    refute has_element?(view, "#vuln-CVE-2024-3094")

    {:ok, view, _} = live(conn, ~p"/hosts/web01?sev=critical&kev=1")
    assert has_element?(view, "#vuln-CVE-2024-6387")
    refute has_element?(view, "#vuln-CVE-2023-48795")
  end

  test "host page tabs and older scans", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/hosts/web01?tab=packages")
    assert html =~ "openssh-server"

    {:ok, view, _html} = live(conn, ~p"/hosts/web01?tab=history")
    [_, older | _] = Vulsweb.Results.history("web01")
    assert has_element?(view, "#scan-#{VulswebWeb.Format.dom_id(older.dir)}")

    {:ok, _view, html} = live(conn, ~p"/hosts/web01?scan=#{older.id}")
    assert html =~ "Viewing an older scan"
  end

  test "unknown host renders a not found state", %{conn: conn} do
    {:ok, _view, html} = live(conn, ~p"/hosts/nope")
    assert html =~ "Host not found"
  end

  test "fleet CVE list filters and links", %{conn: conn} do
    {:ok, view, _html} = live(conn, ~p"/cves?kev=1")
    assert has_element?(view, "#cve-CVE-2024-6387")
    refute has_element?(view, "#cve-CVE-2024-3094")

    {:ok, view, _html} = live(conn, ~p"/cves?q=docker01")
    assert has_element?(view, "#cve-CVE-2022-48174")
  end

  test "CVE detail page", %{conn: conn} do
    {:ok, view, html} = live(conn, ~p"/cves/CVE-2024-6387")
    assert html =~ "Known exploited vulnerability"
    assert html =~ "CWE-364"
    assert has_element?(view, "#affected-hosts", "web01")
    assert has_element?(view, "#cvss-scores", "CVSS:4.0")

    {:ok, _view, html} = live(conn, ~p"/cves/CVE-1999-0001")
    assert html =~ "Not found in current results"
  end
end
