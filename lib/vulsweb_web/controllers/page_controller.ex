defmodule VulswebWeb.PageController do
  use VulswebWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
