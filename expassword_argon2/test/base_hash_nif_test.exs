defmodule ExPassword.Argon2.Base.HashNifTest do
  use ExUnit.Case

  describe "ExPassword.Argon2.Base.hash_nif/3" do
    test "" do
      assert_raise ArgumentError, ~R/salt is too short/i, fn ->
        ExPassword.Argon2.Base.hash_nif("", "", %{threads: 2, memory_cost: 65536, time_cost: 2})
      end
    end
  end
end
