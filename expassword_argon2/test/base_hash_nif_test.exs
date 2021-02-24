if Code.ensure_loaded?(ExPassword.Argon2.Base) do
  defmodule ExPassword.Argon2.Base.HashNifTest do
    use ExUnit.Case

    describe "ExPassword.Argon2.Base.hash_nif/3" do
      test "raises if salt is too short" do
        assert_raise ArgumentError, ~R/salt is too short/i, fn ->
          ExPassword.Argon2.Base.hash_nif("", "", %{type: :argon2id, threads: 2, memory_cost: 65_536, time_cost: 2})
        end
      end
    end
  end
end
