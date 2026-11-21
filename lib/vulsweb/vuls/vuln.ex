defmodule Vulsweb.Vuls.Vuln do
  @moduledoc """
  A compact, per-host row for one detected CVE. Built from a `scannedCves`
  entry by `Vulsweb.Vuls.Report`; the full CVE details are loaded on demand.
  """

  @type fix_status :: :fixable | :unfixed | :unknown

  @type affected :: %{
          kind: :package | :library | :cpe | :wordpress | :github | :windows_kb,
          name: String.t(),
          version: String.t() | nil,
          new_version: String.t() | nil,
          fixed_in: String.t() | nil,
          fix_state: String.t() | nil,
          not_fixed_yet: boolean(),
          path: String.t() | nil
        }

  @type t :: %__MODULE__{
          cve_id: String.t(),
          score: float() | nil,
          severity: Vulsweb.Vuls.Scoring.severity(),
          cvss_version: String.t() | nil,
          cvss_type: String.t() | nil,
          cvss_vector: String.t() | nil,
          summary: String.t() | nil,
          affected: [affected()],
          fix_status: fix_status(),
          kev: boolean(),
          exploits: non_neg_integer(),
          metasploits: non_neg_integer(),
          attack_vector: String.t() | nil,
          confidence: String.t() | nil,
          published: Date.t() | nil,
          cwe_ids: [String.t()],
          diff_status: String.t() | nil
        }

  defstruct cve_id: nil,
            score: nil,
            severity: :unknown,
            cvss_version: nil,
            cvss_type: nil,
            cvss_vector: nil,
            summary: nil,
            affected: [],
            fix_status: :unknown,
            kev: false,
            exploits: 0,
            metasploits: 0,
            attack_vector: nil,
            confidence: nil,
            published: nil,
            cwe_ids: [],
            diff_status: nil

  @doc "Names of the affected packages/libraries, for display and search."
  def affected_names(%__MODULE__{affected: affected}) do
    affected |> Enum.map(& &1.name) |> Enum.uniq()
  end
end
