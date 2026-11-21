defmodule VulswebWeb.Format do
  @moduledoc "Formatting helpers shared by templates."

  @doc "Relative time like `3h ago`."
  def ago(nil), do: "never"

  def ago(%DateTime{} = dt) do
    secs = DateTime.diff(DateTime.utc_now(), dt)

    cond do
      secs < 0 -> "just now"
      secs < 60 -> "just now"
      secs < 3600 -> "#{div(secs, 60)}m ago"
      secs < 86_400 -> "#{div(secs, 3600)}h ago"
      secs < 86_400 * 60 -> "#{div(secs, 86_400)}d ago"
      true -> "#{div(secs, 86_400 * 30)}mo ago"
    end
  end

  @doc "True when a scan is older than VULSWEB_STALE_AFTER hours."
  def stale?(nil), do: true

  def stale?(%DateTime{} = dt) do
    hours = Application.get_env(:vulsweb, :stale_after_hours, 48)
    DateTime.diff(DateTime.utc_now(), dt) > hours * 3600
  end

  def iso(nil), do: nil
  def iso(%DateTime{} = dt), do: DateTime.to_iso8601(dt)

  @doc "Server-side fallback for absolute timestamps (LocalTime hook re-renders it)."
  def datetime(nil), do: "—"
  def datetime(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d %H:%M UTC")

  def date(nil), do: "—"
  def date(%Date{} = d), do: Date.to_iso8601(d)
  def date(%DateTime{} = dt), do: dt |> DateTime.to_date() |> Date.to_iso8601()

  def score(nil), do: "—"
  def score(s) when is_number(s), do: :erlang.float_to_binary(s / 1, decimals: 1)

  def severity_label(:critical), do: "Critical"
  def severity_label(:high), do: "High"
  def severity_label(:medium), do: "Medium"
  def severity_label(:low), do: "Low"
  def severity_label(:unknown), do: "Unknown"

  def fix_label(:fixable), do: "Fix available"
  def fix_label(:unfixed), do: "No fix yet"
  def fix_label(:unknown), do: "Unknown"

  def bytes(n) when n < 1024, do: "#{n} B"
  def bytes(n) when n < 1024 * 1024, do: "#{Float.round(n / 1024, 1)} KB"
  def bytes(n), do: "#{Float.round(n / 1024 / 1024, 1)} MB"

  def number(n) when is_integer(n) do
    n
    |> Integer.to_string()
    |> String.reverse()
    |> String.replace(~r/(\d{3})(?=\d)/, "\\1,")
    |> String.reverse()
  end

  def number(n), do: to_string(n)

  @doc "A string safe to use inside a DOM id / CSS selector."
  def dom_id(s), do: String.replace(s, ~r/[^A-Za-z0-9_-]/, "_")

  @doc "External link for a CVE id."
  def nvd_url(cve_id), do: "https://nvd.nist.gov/vuln/detail/#{cve_id}"

  def source_label(type) do
    case type do
      "nvd" -> "NVD"
      "mitre" -> "MITRE"
      "jvn" -> "JVN"
      "euvd" -> "EUVD"
      "vulncheck" -> "VulnCheck"
      "redhat" -> "Red Hat"
      "redhat_api" -> "Red Hat"
      "ubuntu" -> "Ubuntu"
      "ubuntu_api" -> "Ubuntu"
      "debian" -> "Debian"
      "debian_security_tracker" -> "Debian"
      "amazon" -> "Amazon"
      "oracle" -> "Oracle"
      "alma" -> "AlmaLinux"
      "rocky" -> "Rocky"
      "suse" -> "SUSE"
      "alpine" -> "Alpine"
      "fedora" -> "Fedora"
      "microsoft" -> "Microsoft"
      "github" -> "GitHub"
      "wpscan" -> "WPScan"
      "vendor" -> "Vendor advisory"
      "trivy" -> "Trivy"
      "trivy:" <> src -> "Trivy (#{src})"
      nil -> "—"
      other -> other
    end
  end
end
