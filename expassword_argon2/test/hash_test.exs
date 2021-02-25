defmodule ExPassword.Argon2.HashTest do
  use ExUnit.Case

  describe "ExPassword.Argon2.hash/2" do
    test "ensures a hash is produced with valid options" do
      if Code.ensure_loaded?(ExPassword.Argon2.Base) do
        assert "$argon2i$v=16$m=32,t=1,p=2$" <> _rest = ExPassword.Argon2.hash("", %{type: :argon2i, threads: 2, time_cost: 1, memory_cost: 32, version: 16})
      end
      assert "$argon2i$v=19$m=32,t=1,p=2$" <> _rest = ExPassword.Argon2.hash("", %{type: :argon2i, threads: 2, time_cost: 1, memory_cost: 32})
      assert "$argon2i$v=19$m=32,t=1,p=2$" <> _rest = ExPassword.Argon2.hash("", %{type: :argon2i, threads: 2, time_cost: 1, memory_cost: 32, version: 19})

      if Code.ensure_loaded?(ExPassword.Argon2.Base) do
        assert "$argon2id$v=16$m=32,t=1,p=2$" <> _rest = ExPassword.Argon2.hash("", %{type: :argon2id, threads: 2, time_cost: 1, memory_cost: 32, version: 16})
      end
      assert "$argon2id$v=19$m=32,t=1,p=2$" <> _rest = ExPassword.Argon2.hash("", %{type: :argon2id, threads: 2, time_cost: 1, memory_cost: 32})
      assert "$argon2id$v=19$m=32,t=1,p=2$" <> _rest = ExPassword.Argon2.hash("", %{type: :argon2id, threads: 2, time_cost: 1, memory_cost: 32, version: 19})
    end

    test "raises when options are invalid" do
      assert_raise ArgumentError, fn ->
        ExPassword.Argon2.hash("", %{type: :argon2d, threads: 2, time_cost: 1, memory_cost: 32})
      end
      assert_raise ArgumentError, fn ->
        ExPassword.Argon2.hash("", %{type: :argon2id, threads: nil, time_cost: 1, memory_cost: 32})
      end
      assert_raise ArgumentError, fn ->
        ExPassword.Argon2.hash("", %{type: :argon2id, threads: 2, time_cost: 0, memory_cost: 32})
      end
      assert_raise ArgumentError, fn ->
        ExPassword.Argon2.hash("", %{type: :argon2id, threads: 2, time_cost: 1, memory_cost: 8})
      end
    end
  end
end
