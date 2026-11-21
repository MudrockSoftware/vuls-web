defmodule Vulsweb.Vuls.Scan do
  @moduledoc """
  One vuls result file (`results/<scannedAt>/<server>.json`), summarized.

  Every indexed file keeps its metadata and severity counts. Only the latest
  scan of each host also keeps its `vulns` and `packages` (see
  `Vulsweb.Results.Store`); for history entries those are `nil`.
  """

  alias Vulsweb.Vuls.Vuln

  @type counts :: %{
          critical: non_neg_integer(),
          high: non_neg_integer(),
          medium: non_neg_integer(),
          low: non_neg_integer(),
          unknown: non_neg_integer(),
          total: non_neg_integer(),
          fixable: non_neg_integer(),
          unfixed: non_neg_integer(),
          kev: non_neg_integer(),
          exploitable: non_neg_integer()
        }

  @type package :: %{
          name: String.t(),
          version: String.t(),
          new_version: String.t() | nil,
          arch: String.t() | nil,
          repository: String.t() | nil,
          vulns: non_neg_integer()
        }

  @type t :: %__MODULE__{
          id: String.t(),
          host: String.t(),
          dir: String.t(),
          path: String.t(),
          mtime: integer(),
          size: non_neg_integer(),
          server_name: String.t() | nil,
          container: String.t() | nil,
          family: String.t() | nil,
          release: String.t() | nil,
          kernel_release: String.t() | nil,
          kernel_version: String.t() | nil,
          reboot_required: boolean(),
          ipv4: [String.t()],
          ipv6: [String.t()],
          platform: String.t() | nil,
          scan_mode: String.t() | nil,
          scanned_via: String.t() | nil,
          scanned_by: String.t() | nil,
          scanned_version: String.t() | nil,
          reported_version: String.t() | nil,
          scanned_at: DateTime.t() | nil,
          reported_at: DateTime.t() | nil,
          errors: [String.t()],
          warnings: [String.t()],
          counts: counts(),
          packages_count: non_neg_integer(),
          upgradable_count: non_neg_integer(),
          libraries_count: non_neg_integer(),
          vulns: [Vuln.t()] | nil,
          packages: [package()] | nil,
          parse_error: String.t() | nil
        }

  defstruct id: nil,
            host: nil,
            dir: nil,
            path: nil,
            mtime: 0,
            size: 0,
            server_name: nil,
            container: nil,
            family: nil,
            release: nil,
            kernel_release: nil,
            kernel_version: nil,
            reboot_required: false,
            ipv4: [],
            ipv6: [],
            platform: nil,
            scan_mode: nil,
            scanned_via: nil,
            scanned_by: nil,
            scanned_version: nil,
            reported_version: nil,
            scanned_at: nil,
            reported_at: nil,
            errors: [],
            warnings: [],
            counts: %{
              critical: 0,
              high: 0,
              medium: 0,
              low: 0,
              unknown: 0,
              total: 0,
              fixable: 0,
              unfixed: 0,
              kev: 0,
              exploitable: 0
            },
            packages_count: 0,
            upgradable_count: 0,
            libraries_count: 0,
            vulns: nil,
            packages: nil,
            parse_error: nil

  @doc "Drops the heavy per-CVE and per-package lists (for history entries)."
  def strip(%__MODULE__{} = scan), do: %{scan | vulns: nil, packages: nil}

  @doc "Human OS label, e.g. `ubuntu 24.04`."
  def os_label(%__MODULE__{family: nil}), do: nil
  def os_label(%__MODULE__{family: f, release: r}), do: String.trim("#{f} #{r}")

  @doc "Timestamp used for ordering: scannedAt, falling back to file mtime."
  def sort_time(%__MODULE__{scanned_at: %DateTime{} = t}), do: DateTime.to_unix(t)
  def sort_time(%__MODULE__{mtime: mtime}), do: mtime
end
