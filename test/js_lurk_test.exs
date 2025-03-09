defmodule JSLurkTest do
  use ExUnit.Case
  doctest JSLurk

  test "greets the world" do
    assert JSLurk.hello() == :world
  end
end
