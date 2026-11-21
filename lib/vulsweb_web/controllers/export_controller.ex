defmodule VulswebWeb.ExportController do
  use VulswebWeb, :controller

  alias Vulsweb.Results
  alias Vulsweb.Results.Filter
  alias Vulsweb.Vuls.Vuln

  @doc "Fleet-wide CVE list, honoring the same filters as /cves."
  def cves(conn, params) do
    rows = Filter.cves(Results.cves(), Filter.normalize(params))

    header =
      ~w(cve_id severity score cvss_version kev exploits hosts host_count fixable_hosts packages published summary)

    lines =
      for r <- rows do
        [
          r.cve_id,
          r.severity,
          score(r.score),
          r.cvss_version,
          r.kev,
          r.exploits,
          Enum.join(r.hosts, " "),
          length(r.hosts),
          r.fixable_hosts,
          Enum.join(r.packages, " "),
          r.published,
          r.summary
        ]
      end

    send_csv(conn, "vulsweb-cves-#{Date.utc_today()}.csv", [header | lines])
  end

  @doc "CVE list of one host (latest scan or ?scan=<id>), honoring the host page filters."
  def host(conn, %{"host" => host} = params) do
    scan =
      case params["scan"] do
        id when is_binary(id) and id != "" ->
          case Results.scan(host, id) do
            {:ok, scan} -> scan
            _ -> nil
          end

        _ ->
          Results.host(host)
      end

    case scan do
      nil ->
        conn |> put_status(:not_found) |> text("host not found")

      scan ->
        rows = Filter.vulns(scan.vulns, Filter.normalize(params))

        header =
          ~w(host scanned_at cve_id severity score cvss_version cvss_source fix_status kev exploits packages installed fixed_in published summary)

        lines =
          for v <- rows do
            [
              host,
              scan.scanned_at && DateTime.to_iso8601(scan.scanned_at),
              v.cve_id,
              v.severity,
              score(v.score),
              v.cvss_version,
              v.cvss_type,
              v.fix_status,
              v.kev,
              v.exploits + v.metasploits,
              Vuln.affected_names(v) |> Enum.join(" "),
              v.affected |> Enum.map(& &1.version) |> Enum.reject(&is_nil/1) |> Enum.join(" "),
              v.affected
              |> Enum.map(&(&1.fixed_in || &1.new_version))
              |> Enum.reject(&is_nil/1)
              |> Enum.join(" "),
              v.published,
              v.summary
            ]
          end

        safe = String.replace(host, ~r/[^A-Za-z0-9._@-]/, "_")
        send_csv(conn, "vulsweb-#{safe}-#{Date.utc_today()}.csv", [header | lines])
    end
  end

  defp send_csv(conn, filename, rows) do
    body = Enum.map(rows, fn row -> [Enum.map_intersperse(row, ",", &cell/1), "\r\n"] end)

    conn
    |> put_resp_content_type("text/csv")
    |> put_resp_header("content-disposition", ~s(attachment; filename="#{filename}"))
    |> send_resp(200, body)
  end

  defp score(nil), do: nil
  defp score(s), do: :erlang.float_to_binary(s / 1, decimals: 1)

  # RFC 4180 quoting, plus neutralizing spreadsheet formula injection.
  defp cell(nil), do: ""
  defp cell(v) when is_atom(v), do: Atom.to_string(v)
  defp cell(v) when is_integer(v), do: Integer.to_string(v)
  defp cell(%Date{} = d), do: Date.to_iso8601(d)

  defp cell(v) when is_binary(v) do
    v = if String.starts_with?(v, ["=", "+", "-", "@", "\t", "\r"]), do: "'" <> v, else: v

    if String.contains?(v, [",", "\"", "\n", "\r"]),
      do: ~s("#{String.replace(v, "\"", "\"\"")}"),
      else: v
  end

  defp cell(v), do: to_string(v)
end
