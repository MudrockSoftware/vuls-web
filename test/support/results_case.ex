defmodule Vulsweb.ResultsCase do
  @moduledoc """
  Starts a `Vulsweb.Results.Store` over a fresh temporary results directory
  filled with `Vulsweb.Sample` data. The store uses named ETS tables, so
  these tests are not async.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      import Vulsweb.ResultsCase
    end
  end

  setup tags do
    dir = Path.join(System.tmp_dir!(), "vulsweb-test-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)
    on_exit(fn -> File.rm_rf!(dir) end)

    unless tags[:empty], do: Vulsweb.Sample.generate(dir)

    start_supervised!({Vulsweb.Results.Store, dir: dir, interval: :manual, settle_seconds: 0})
    :ok = Vulsweb.Results.refresh()

    {:ok, results_dir: dir}
  end

  @doc "Writes a result document for `host` scanned at `at` and returns its path."
  def write_result(dir, host, %DateTime{} = at, doc) do
    sub = Path.join(dir, Vulsweb.Sample.dirname(at))
    File.mkdir_p!(sub)
    path = Path.join(sub, host <> ".json")
    File.write!(path, Jason.encode!(doc))
    File.touch!(path, DateTime.to_unix(at))
    path
  end

  @doc "Minimal vuls result with the given scannedCves."
  def minimal_result(host, at, cves) do
    %{
      "jsonVersion" => 4,
      "serverName" => host,
      "family" => "ubuntu",
      "release" => "24.04",
      "scannedAt" => DateTime.to_iso8601(at),
      "runningKernel" => %{"release" => "6.8.0", "rebootRequired" => false},
      "packages" => %{
        "openssl" => %{"name" => "openssl", "version" => "3.0.13", "newVersion" => "3.0.14"}
      },
      "errors" => [],
      "warnings" => [],
      "scannedCves" =>
        Map.new(cves, fn {id, score} ->
          {id,
           %{
             "cveID" => id,
             "affectedPackages" => [%{"name" => "openssl", "fixedIn" => "3.0.14"}],
             "cveContents" => %{
               "nvd" => [
                 %{
                   "type" => "nvd",
                   "cveID" => id,
                   "summary" => "test #{id}",
                   "cvss3Score" => score
                 }
               ]
             }
           }}
        end)
    }
  end
end
