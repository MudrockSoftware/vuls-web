defmodule Vulsweb.ParentWatch do
  @moduledoc """
  Stops the VM when the burrito_ng wrapper process goes away.

  The wrapper runs the BEAM as a child process but does not forward signals,
  so `kill <wrapper>` (or a supervisor stopping only the main pid) would leave
  an orphaned BEAM behind that still holds the HTTP port. We remember our
  parent pid at boot and shut down cleanly once we get re-parented.
  Linux only (reads /proc).
  """

  use GenServer
  require Logger

  @interval 1_000

  def child_spec(_opts) do
    %{id: __MODULE__, start: {__MODULE__, :start_link, []}, restart: :transient}
  end

  @doc "The child spec when running inside a burrito_ng binary on Linux, else nil."
  def maybe_child do
    if System.get_env("__BURRITO_NG") == "1" and ppid() != nil, do: __MODULE__
  end

  def start_link, do: GenServer.start_link(__MODULE__, ppid())

  @impl true
  def init(parent) do
    schedule()
    {:ok, parent}
  end

  @impl true
  def handle_info(:check, parent) do
    case ppid() do
      ^parent ->
        schedule()
        {:noreply, parent}

      _other ->
        Logger.info("launcher process #{parent} exited, shutting down")
        System.stop(0)
        {:stop, :normal, parent}
    end
  end

  defp schedule, do: Process.send_after(self(), :check, @interval)

  # Field 4 of /proc/self/stat. The command name (field 2) may contain spaces,
  # so split after its closing paren.
  defp ppid do
    with {:ok, stat} <- File.read("/proc/self/stat"),
         [_, rest] <- String.split(stat, ") ", parts: 2),
         [_state, ppid | _] <- String.split(rest, " "),
         {pid, ""} <- Integer.parse(ppid) do
      pid
    else
      _ -> nil
    end
  end
end
