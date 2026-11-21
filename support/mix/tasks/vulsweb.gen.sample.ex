defmodule Mix.Tasks.Vulsweb.Gen.Sample do
  @shortdoc "Writes sample vuls result files for development"
  @moduledoc """
  Writes realistic vuls result files (several hosts, three scans each).

      mix vulsweb.gen.sample [DIR]

  DIR defaults to `sample/results`, the dev default of VULS_RESULTS_DIR.
  """
  use Mix.Task

  @impl true
  def run(args) do
    dir = List.first(args) || "sample/results"
    Mix.Task.run("app.config")
    {:ok, _} = Application.ensure_all_started(:jason)
    paths = Vulsweb.Sample.generate(dir)
    Mix.shell().info("wrote #{length(paths)} result files to #{dir}")
  end
end
