defmodule VulswebWeb.ErrorJSONTest do
  use VulswebWeb.ConnCase, async: true

  test "renders 404" do
    assert VulswebWeb.ErrorJSON.render("404.json", %{}) == %{errors: %{detail: "Not Found"}}
  end

  test "renders 500" do
    assert VulswebWeb.ErrorJSON.render("500.json", %{}) ==
             %{errors: %{detail: "Internal Server Error"}}
  end
end
