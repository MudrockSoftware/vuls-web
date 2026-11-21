defmodule Vulsweb.Vuls.Compat do
  @moduledoc """
  Reads vuls result files and normalizes older layouts to the current one,
  so the rest of the app only deals with a single shape.

  Every vuls release since v0.5.0 (2018) writes `"jsonVersion": 4`, but the
  layout inside v4 changed over time:

    * < v0.15.14: `cveContents.<type>` is a single object, now a list
    * < v0.19.0:  `alertDict` is `{en, ja}` (US-CERT, JPCERT), now
      `{cisa, jpcert, uscert}`
    * v0.9 - v0.12: library scan results are under `libScanners`, now `libraries`
    * older GitHub security alerts carry `packageName` instead of `package.name`

  Files written by vuls before v0.5.0 (jsonVersion 2 and 3) use a different
  format and are rejected with an explanatory error.
  """

  @current_version 4

  @doc "Reads, decodes and normalizes a result file."
  @spec read_file(Path.t()) :: {:ok, map()} | {:error, String.t()}
  def read_file(path) do
    with {:ok, body} <- read(path),
         {:ok, doc} <- decode(body) do
      normalize(doc)
    end
  end

  @doc "Normalizes a decoded result document."
  @spec normalize(map()) :: {:ok, map()} | {:error, String.t()}
  def normalize(%{"jsonVersion" => v}) when is_integer(v) and v < @current_version do
    {:error,
     "unsupported result format (jsonVersion #{v}, written by vuls older than v0.5.0); " <>
       "re-run the scan with a current vuls"}
  end

  def normalize(doc) when is_map(doc) do
    if legacy?(doc) do
      {:error,
       "unsupported result format (written by vuls older than v0.5.0); " <>
         "re-run the scan with a current vuls"}
    else
      {:ok, normalize_v4(doc)}
    end
  end

  def normalize(_), do: {:error, "not a vuls result (JSON is not an object)"}

  # vuls <= v0.3 had no jsonVersion and wrote Go field names (ScannedCves,
  # KnownCves) with CVEs as lists.
  defp legacy?(doc) do
    Map.has_key?(doc, "ScannedCves") or Map.has_key?(doc, "KnownCves") or
      is_list(doc["scannedCves"])
  end

  defp normalize_v4(doc) do
    doc
    |> update_map("scannedCves", fn cves -> Map.new(cves, fn {id, v} -> {id, vuln(v)} end) end)
    |> libraries()
  end

  defp vuln(v) when is_map(v) do
    v
    |> update_map("cveContents", fn contents ->
      Map.new(contents, fn {type, c} -> {type, contents_list(c)} end)
    end)
    |> update_map("alertDict", &alert_dict/1)
    |> update_list("gitHubSecurityAlerts", &github_alerts/1)
  end

  defp vuln(v), do: v

  defp contents_list(c) when is_list(c), do: c
  defp contents_list(c) when is_map(c), do: [c]
  defp contents_list(_), do: []

  # Before v0.19.0: %{"en" => US-CERT alerts, "ja" => JPCERT alerts}.
  defp alert_dict(%{} = dict) do
    {en, dict} = Map.pop(dict, "en")
    {ja, dict} = Map.pop(dict, "ja")

    dict
    |> Map.update("uscert", list(en), &(list(&1) ++ list(en)))
    |> Map.update("jpcert", list(ja), &(list(&1) ++ list(ja)))
  end

  defp github_alerts(alerts) when is_list(alerts) do
    Enum.map(alerts, fn
      %{"packageName" => name} = a when is_binary(name) and not is_map_key(a, "package") ->
        Map.put(a, "package", %{"name" => name})

      a ->
        a
    end)
  end

  defp libraries(%{"libraries" => _} = doc), do: doc
  defp libraries(%{"libScanners" => libs} = doc), do: Map.put(doc, "libraries", libs)
  defp libraries(doc), do: doc

  defp update_map(map, key, fun) do
    case map do
      %{^key => %{} = value} -> Map.put(map, key, fun.(value))
      _ -> map
    end
  end

  defp update_list(map, key, fun) do
    case map do
      %{^key => value} when is_list(value) -> Map.put(map, key, fun.(value))
      _ -> map
    end
  end

  defp list(l) when is_list(l), do: l
  defp list(_), do: []

  defp read(path) do
    case File.read(path) do
      {:ok, body} -> {:ok, body}
      {:error, reason} -> {:error, "cannot read file: #{:file.format_error(reason)}"}
    end
  end

  defp decode(body) do
    case Jason.decode(body) do
      {:ok, doc} -> {:ok, doc}
      {:error, e} -> {:error, "invalid JSON: " <> Exception.message(e)}
    end
  end
end
