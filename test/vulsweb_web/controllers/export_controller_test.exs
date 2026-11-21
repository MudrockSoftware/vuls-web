defmodule VulswebWeb.ExportControllerTest do
  use VulswebWeb.ConnCase, async: false
  use Vulsweb.ResultsCase

  test "fleet CSV honors filters", %{conn: conn} do
    conn = get(conn, ~p"/export/cves.csv?kev=1")
    assert response_content_type(conn, :csv)
    [header | rows] = conn |> response(200) |> String.split("\r\n", trim: true)
    assert header =~ "cve_id,severity,score"
    assert Enum.any?(rows, &String.starts_with?(&1, "CVE-2024-6387,critical,9.2"))
    refute Enum.any?(rows, &String.starts_with?(&1, "CVE-2024-3094"))
  end

  test "host CSV", %{conn: conn} do
    body = conn |> get(~p"/hosts/db01/export.csv") |> response(200)
    assert body =~ "host,scanned_at,cve_id"
    assert body =~ "db01,"
  end

  test "unknown host CSV is a 404", %{conn: conn} do
    assert conn |> get(~p"/hosts/nope/export.csv") |> response(404)
  end
end
