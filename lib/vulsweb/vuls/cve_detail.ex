defmodule Vulsweb.Vuls.CveDetail do
  @moduledoc """
  Full details for one CVE, built from the raw `scannedCves` entries of one
  or more result files (contents differ per distro, so they are merged).
  """

  alias Vulsweb.Vuls.{Report, Scoring}

  @doc """
  Merges raw vuln maps (one per sampled result file) into a single raw vuln.
  `cveContents` are unioned per source, list fields are de-duplicated.
  """
  @spec merge([map()]) :: map()
  def merge([single]), do: single

  def merge(raws) do
    Enum.reduce(raws, %{}, fn raw, acc ->
      Map.merge(acc, raw, fn
        "cveContents", a, b when is_map(a) and is_map(b) ->
          Map.merge(a, b, fn _type, x, y -> Enum.uniq(List.wrap(x) ++ List.wrap(y)) end)

        "alertDict", a, b when is_map(a) and is_map(b) ->
          Map.merge(a, b, fn _team, x, y -> Enum.uniq(List.wrap(x) ++ List.wrap(y)) end)

        _key, a, b when is_list(a) and is_list(b) ->
          Enum.uniq(a ++ b)

        _key, a, _b ->
          a
      end)
    end)
  end

  @doc "Builds the detail view. `cwe_dict` is the result file's `cweDict`."
  @spec build(String.t(), map(), map(), String.t() | nil) :: map()
  def build(cve_id, raw, cwe_dict, family) do
    contents = contents(raw, family)
    max = Scoring.max_score(raw)

    %{
      cve_id: cve_id,
      max: max,
      severity: Scoring.severity(max && max.score),
      scores: Scoring.all_scores(raw),
      title: Enum.find_value(contents, & &1.title),
      summary: Enum.find_value(contents, & &1.summary),
      contents: contents,
      published: contents |> Enum.map(& &1.published) |> Enum.reject(&is_nil/1) |> min_dt(),
      last_modified:
        contents |> Enum.map(& &1.last_modified) |> Enum.reject(&is_nil/1) |> max_dt(),
      references: references(contents),
      cwes: cwes(contents, cwe_dict),
      attack_vector: Scoring.attack_vector(raw),
      ssvc: Enum.find_value(contents, & &1.ssvc),
      exploits: exploits(raw),
      metasploits: metasploits(raw),
      kevs: kevs(raw),
      alerts: alerts(raw),
      mitigations: mitigations(raw),
      advisories: advisories(raw),
      cpes: contents |> Enum.flat_map(& &1.cpes) |> Enum.uniq(),
      ctis: list(raw["ctis"])
    }
  end

  defp contents(raw, family) do
    conts = map(raw["cveContents"])
    keys = Map.keys(conts)
    trivy = keys |> Enum.filter(&String.starts_with?(&1, "trivy")) |> Enum.sort()
    order = ~w(nvd mitre vulncheck euvd) ++ Report.family_types(family) ++ trivy
    order = Enum.filter(order, &(&1 in keys)) ++ Enum.sort(keys -- order)

    for type <- order, c <- list(conts[type]) do
      %{
        type: type,
        title: blank(c["title"]),
        summary: blank(c["summary"]),
        source_link: blank(c["sourceLink"]),
        published: time(c["published"]),
        last_modified: time(c["lastModified"]),
        cwe_ids: list(c["cweIDs"]),
        references:
          for r <- list(c["references"]), blank(r["link"]) do
            %{link: r["link"], source: blank(r["source"]), tags: list(r["tags"])}
          end,
        cpes: c["cpes"] |> list() |> Enum.map(&(&1["uri"] || &1["formattedString"])),
        ssvc: ssvc(c["ssvc"]),
        source: get_in(c, ["optional", "source"])
      }
    end
  end

  defp ssvc(%{} = s) do
    m = %{
      exploitation: blank(s["exploitation"]),
      automatable: blank(s["automatable"]),
      technical_impact: blank(s["technical_impact"])
    }

    if Enum.any?(Map.values(m)), do: m
  end

  defp ssvc(_), do: nil

  defp references(contents) do
    source_links =
      for c <- contents, c.source_link, do: %{link: c.source_link, source: c.type, tags: []}

    (source_links ++ Enum.flat_map(contents, & &1.references))
    |> Enum.uniq_by(& &1.link)
  end

  defp cwes(contents, cwe_dict) do
    contents
    |> Enum.flat_map(& &1.cwe_ids)
    |> Enum.uniq()
    |> Enum.sort()
    |> Enum.map(fn id ->
      num = String.replace_prefix(id, "CWE-", "")
      entry = map(cwe_dict[num])
      en = map(entry["en"])

      %{
        id: id,
        name: blank(en["name"]),
        url:
          if(Regex.match?(~r/^\d+$/, num),
            do: "https://cwe.mitre.org/data/definitions/#{num}.html"
          ),
        top25: map(entry["cweTopTwentyfives"]) |> Map.keys() |> Enum.sort(),
        owasp: map(entry["owaspTopTens"]) |> Map.keys() |> Enum.sort()
      }
    end)
  end

  defp exploits(raw) do
    for e <- list(raw["exploits"]) do
      %{
        type: blank(e["exploitType"]),
        id: blank(e["id"]),
        url: blank(e["url"]),
        description: blank(e["description"])
      }
    end
    |> Enum.uniq_by(&(&1.url || &1.id))
  end

  defp metasploits(raw) do
    for m <- list(raw["metasploits"]) do
      %{
        name: blank(m["name"]),
        title: blank(m["title"]),
        description: blank(m["description"]),
        urls: list(m["URLs"])
      }
    end
  end

  defp kevs(raw) do
    kevs =
      for k <- list(raw["kevs"]) do
        %{
          type: blank(k["type"]),
          vendor_project: blank(k["vendor_project"]),
          product: blank(k["product"]),
          name: blank(k["vulnerability_name"]),
          description: blank(k["short_description"]),
          required_action: blank(k["required_action"]),
          ransomware: blank(k["known_ransomware_campaign_use"]),
          date_added: time(k["date_added"]),
          due_date: time(k["due_date"])
        }
      end

    # Older JSON (before `kevs`) stored CISA KEV entries in alertDict.cisa.
    legacy =
      if kevs == [] do
        for a <- list(get_in(map(raw["alertDict"]), ["cisa"])) do
          %{
            type: "cisa",
            vendor_project: nil,
            product: nil,
            name: blank(a["title"]),
            description: nil,
            required_action: nil,
            ransomware: nil,
            date_added: nil,
            due_date: nil
          }
        end
      else
        []
      end

    kevs ++ legacy
  end

  defp alerts(raw) do
    dict = map(raw["alertDict"])

    for team <- ["uscert", "jpcert"], a <- list(dict[team]) do
      %{team: team, title: blank(a["title"]), url: blank(a["url"])}
    end
  end

  defp mitigations(raw) do
    for m <- list(raw["mitigations"]) do
      %{type: blank(m["cveContentType"]), text: blank(m["mitigation"]), url: blank(m["url"])}
    end
  end

  defp advisories(raw) do
    for a <- list(raw["distroAdvisories"]) do
      %{
        id: blank(a["advisoryID"]),
        severity: blank(a["severity"]),
        issued: time(a["issued"]),
        description: blank(a["description"])
      }
    end
    |> Enum.uniq_by(& &1.id)
  end

  defp min_dt([]), do: nil
  defp min_dt(l), do: Enum.min(l, DateTime)
  defp max_dt([]), do: nil
  defp max_dt(l), do: Enum.max(l, DateTime)

  defp time(s) when is_binary(s) do
    case DateTime.from_iso8601(s) do
      {:ok, %DateTime{year: 1}, _} -> nil
      {:ok, dt, _} -> dt
      _ -> nil
    end
  end

  defp time(_), do: nil

  defp map(m) when is_map(m), do: m
  defp map(_), do: %{}

  defp list(l) when is_list(l), do: l
  defp list(_), do: []

  defp blank(s) when is_binary(s) do
    if String.trim(s) == "", do: nil, else: s
  end

  defp blank(_), do: nil
end
