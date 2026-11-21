defmodule VulswebWeb.HealthAndAuthTest do
  use VulswebWeb.ConnCase, async: false
  use Vulsweb.ResultsCase

  test "healthz reports readiness", %{conn: conn} do
    assert %{"status" => "ready", "files" => 15} = conn |> get(~p"/healthz") |> json_response(200)
  end

  test "no auth by default", %{conn: conn} do
    assert Application.get_env(:vulsweb, :basic_auth) == nil
    assert conn |> get(~p"/") |> html_response(200) =~ "Fleet overview"
    assert conn |> get(~p"/export/cves.csv") |> response(200)
  end

  describe "basic auth (VULSWEB_AUTH_USER / VULSWEB_AUTH_PASSWORD)" do
    setup do
      Application.put_env(:vulsweb, :basic_auth, username: "admin", password: "s3cret")
      on_exit(fn -> Application.delete_env(:vulsweb, :basic_auth) end)
    end

    test "protects pages and exports but not healthz", %{conn: conn} do
      assert conn |> get(~p"/") |> response(401)
      assert conn |> get(~p"/export/cves.csv") |> response(401)
      assert conn |> get(~p"/healthz") |> response(200)

      authed =
        put_req_header(conn, "authorization", Plug.BasicAuth.encode_basic_auth("admin", "s3cret"))

      assert authed |> get(~p"/") |> html_response(200) =~ "Fleet overview"

      wrong =
        put_req_header(conn, "authorization", Plug.BasicAuth.encode_basic_auth("admin", "nope"))

      assert wrong |> get(~p"/") |> response(401)
    end
  end
end
