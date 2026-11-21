defmodule VulswebWeb.ConnCase do
  @moduledoc """
  Test case for tests that require setting up a connection.
  """

  use ExUnit.CaseTemplate

  using do
    quote do
      @endpoint VulswebWeb.Endpoint

      use VulswebWeb, :verified_routes

      import Plug.Conn
      import Phoenix.ConnTest
      import VulswebWeb.ConnCase
    end
  end

  setup _tags do
    {:ok, conn: Phoenix.ConnTest.build_conn()}
  end
end
