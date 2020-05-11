defmodule ExPassword.Argon2.HashTest do
  use ExUnit.Case

  describe "ExPassword.Argon2.hash/2" do
    test "" do
      assert_raise ArgumentError, ~R/salt is too short/i, fn ->
        ExPassword.Argon2.hash("", %{salt: "", threads: 2, memory_cost: 65536, time_cost: 2})
      end
    end
  end
end
