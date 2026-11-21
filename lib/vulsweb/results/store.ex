defmodule Vulsweb.Results.Store do
  @moduledoc """
  Indexes the vuls results directory and serves it from ETS.

  `vuls server -to-localfile` writes one file per POSTed scan to
  `<results_dir>/<scannedAt>/<server>.json`. Because the directory name is the
  scan time *of that host*, hosts end up in different directories, so the
  "current" state is the newest file of each host across all directories.

  The store polls the tree every `:refresh_interval` ms, re-parses only new or
  changed files (by mtime + size), keeps the full summary (CVE rows, packages)
  for the latest scan of every host and only counts for older scans, then
  broadcasts `{:results_updated, hosts}` on the `"results"` PubSub topic.
  """

  use GenServer
  require Logger

  alias Vulsweb.Vuls.{Compat, Report, Scan}

  @hosts_table :vulsweb_hosts
  @history_table :vulsweb_history
  @meta_table :vulsweb_meta

  @topic "results"
  # Files modified more recently than this are picked up on the next poll, so
  # we never parse a result vuls is still writing.
  @settle_seconds 2

  def topic, do: @topic
  def hosts_table, do: @hosts_table
  def history_table, do: @history_table
  def meta_table, do: @meta_table

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: Keyword.get(opts, :name, __MODULE__))
  end

  @doc "Re-scans the results directory now and waits for it to finish."
  def refresh(server \\ __MODULE__), do: GenServer.call(server, :refresh, :infinity)

  @impl true
  def init(opts) do
    dir = Keyword.fetch!(opts, :dir)
    interval = Keyword.get(opts, :interval, 15_000)
    settle = Keyword.get(opts, :settle_seconds, @settle_seconds)

    for t <- [@hosts_table, @history_table, @meta_table] do
      :ets.new(t, [:named_table, :set, :protected, read_concurrency: true])
    end

    state = %{
      dir: dir,
      interval: interval,
      settle: settle,
      # id => %Scan{} (full for the latest scan of each host, stripped otherwise)
      scans: %{},
      latest: %{},
      status: %{dir: dir, state: :indexing, error: nil, refreshed_at: nil, files: 0, failed: 0}
    }

    put_status(state.status)
    :ets.insert(@meta_table, {:cves, []})
    send(self(), :refresh)
    {:ok, state}
  end

  @impl true
  def handle_call(:refresh, _from, state) do
    state = do_refresh(state)
    {:reply, :ok, state}
  end

  @impl true
  def handle_info(:refresh, state) do
    state = do_refresh(state)
    if is_integer(state.interval), do: Process.send_after(self(), :refresh, state.interval)
    {:noreply, state}
  end

  # -- indexing ---------------------------------------------------------------

  defp do_refresh(state) do
    started = System.monotonic_time(:millisecond)

    case list_files(state.dir, state.settle) do
      {:ok, files} ->
        state = apply_changes(state, files)
        ms = System.monotonic_time(:millisecond) - started

        status = %{
          state.status
          | state: :ready,
            error: nil,
            refreshed_at: DateTime.utc_now(),
            files: map_size(state.scans),
            failed: Enum.count(state.scans, fn {_, s} -> s.parse_error end)
        }

        if status.files != state.status.files or state.status.state != :ready do
          Logger.info("indexed #{status.files} result files from #{state.dir} in #{ms}ms")
        end

        put_status(status)
        %{state | status: status}

      {:error, reason} ->
        status = %{state.status | state: :error, error: reason, refreshed_at: DateTime.utc_now()}

        if state.status.error != reason do
          Logger.warning("cannot read results directory #{state.dir}: #{reason}")
        end

        put_status(status)
        %{state | status: status}
    end
  end

  defp apply_changes(state, files) do
    current = Map.new(files, &{&1.id, &1})

    removed = Map.keys(state.scans) -- Map.keys(current)

    changed =
      Enum.filter(files, fn f ->
        case state.scans[f.id] do
          %Scan{mtime: m, size: s} -> m != f.mtime or s != f.size
          nil -> true
        end
      end)

    if removed == [] and changed == [] do
      state
    else
      # Keep full details only for files that may become the latest of a host.
      candidates = latest_candidates(files)

      parsed =
        changed
        |> Task.async_stream(&parse(&1, MapSet.member?(candidates, &1.id)),
          max_concurrency: max(2, div(System.schedulers_online(), 2)),
          timeout: :infinity,
          ordered: false
        )
        |> Map.new(fn {:ok, scan} -> {scan.id, scan} end)

      scans = state.scans |> Map.drop(removed) |> Map.merge(parsed)

      affected_hosts =
        (Enum.map(changed, & &1.host) ++ Enum.map(removed, &state.scans[&1].host))
        |> Enum.uniq()

      state = rebuild(%{state | scans: scans}, affected_hosts, current)

      Phoenix.PubSub.broadcast(Vulsweb.PubSub, @topic, {:results_updated, affected_hosts})
      state
    end
  end

  # Rebuilds latest + history for the given hosts and writes them to ETS.
  defp rebuild(state, hosts, current) do
    by_host = Enum.group_by(Map.values(state.scans), & &1.host)

    state =
      Enum.reduce(hosts, state, fn host, state ->
        case Map.get(by_host, host, []) |> Enum.sort_by(&Scan.sort_time/1, :desc) do
          [] ->
            :ets.delete(@hosts_table, host)
            :ets.delete(@history_table, host)
            %{state | latest: Map.delete(state.latest, host)}

          sorted ->
            # A broken newest file (e.g. truncated) must not hide the last good scan.
            latest = Enum.find(sorted, hd(sorted), &is_nil(&1.parse_error))

            latest =
              if latest.vulns == nil,
                do: parse(Map.fetch!(current, latest.id), true),
                else: latest

            history =
              Enum.map(sorted, fn s -> if s.id == latest.id, do: latest, else: Scan.strip(s) end)

            scans = Enum.reduce(history, state.scans, &Map.put(&2, &1.id, &1))

            :ets.insert(@hosts_table, {host, Scan.strip(latest), latest})
            :ets.insert(@history_table, {host, Enum.map(history, &Scan.strip/1)})
            %{state | scans: scans, latest: Map.put(state.latest, host, latest.id)}
        end
      end)

    :ets.insert(@meta_table, {:cves, Vulsweb.Results.Aggregate.cves(latest_scans(state))})
    state
  end

  defp latest_scans(state), do: Enum.map(state.latest, fn {_host, id} -> state.scans[id] end)

  defp latest_candidates(files) do
    files
    |> Enum.group_by(& &1.host)
    |> Enum.map(fn {_host, fs} -> Enum.max_by(fs, &file_time/1).id end)
    |> MapSet.new()
  end

  defp file_time(f) do
    case Report.dir_time(f.dir) do
      %DateTime{} = dt -> DateTime.to_unix(dt)
      nil -> f.mtime
    end
  end

  defp parse(file, keep_details?) do
    scan =
      case Compat.read_file(file.path) do
        {:ok, doc} -> Report.summarize(doc, file)
        {:error, reason} -> Report.failed(file, reason)
      end

    if keep_details?, do: scan, else: Scan.strip(scan)
  rescue
    e ->
      Logger.error("failed to summarize #{file.path}: " <> Exception.message(e))
      Report.failed(file, "failed to summarize: " <> Exception.message(e))
  end

  # results/<dir>/<host>.json, skipping symlinks (e.g. a `current` link from
  # `vuls scan`) and the `*_diff.json` files written by `vuls report -diff`.
  @doc false
  def list_files(dir, settle \\ @settle_seconds) do
    now = System.os_time(:second)

    case File.ls(dir) do
      {:ok, entries} ->
        listed =
          for entry <- entries,
              sub = Path.join(dir, entry),
              {:ok, %File.Stat{type: :directory}} <- [File.lstat(sub)] do
            {entry, sub, File.ls(sub)}
          end

        denied = for {entry, _sub, {:error, :eacces}} <- listed, do: entry

        files =
          for {entry, sub, {:ok, names}} <- listed,
              name <- names,
              String.ends_with?(name, ".json"),
              not String.ends_with?(name, "_diff.json"),
              path = Path.join(sub, name),
              {:ok, %File.Stat{type: :regular, size: size, mtime: mtime}} <-
                [File.lstat(path, time: :posix)],
              mtime <= now - settle do
            %{
              id: entry <> "/" <> name,
              host: Path.basename(name, ".json"),
              dir: entry,
              path: path,
              mtime: mtime,
              size: size
            }
          end

        cond do
          # vuls creates result dirs with mode 0700 (files 0600) as its own
          # user, typically root. Say so instead of showing an empty fleet.
          denied != [] and files == [] ->
            {:error,
             "permission denied reading #{length(denied)} result directories " <>
               "(vuls writes them with mode 0700; run vulsweb as the same user as vuls)"}

          denied != [] ->
            Logger.warning(
              "permission denied reading result directories: #{Enum.join(denied, ", ")}"
            )

            {:ok, files}

          true ->
            {:ok, files}
        end

      {:error, :enoent} ->
        {:error, "directory does not exist"}

      {:error, reason} ->
        {:error, :file.format_error(reason) |> to_string()}
    end
  end

  defp put_status(status), do: :ets.insert(@meta_table, {:status, status})
end
