defmodule ExPassword.Argon2.NeedsRehashTest do
  use ExUnit.Case

  if false do
    defp to_h(options = %{type: type, memory_cost: m, time_cost: t, threads: p}) do
      v = Map.get(options, :version)
      to_h(type, v, m, t, p)
    end

    defp v(nil), do: []
    defp v(v), do: ["v=", to_string(v)]

    defp to_h(type, v, m, t, p) do
      ["$", to_string(type), "$"]
      |> Kernel.++(v(v))
      |> Kernel.++(["m=", to_string(m), ",t=", to_string(t), ",p=", to_string(p), "$ the rest doesn't matter"])
      |> Enum.join("")
    end
  end

  defp to_opt(type, v, m, t, p) do
    %{type: type, version: v, memory_cost: m, threads: p, time_cost: t}
  end

  describe "ExPassword.Argon2.needs_rehash?/2" do
    test "argon2i" do
      options = to_opt(:argon2i, 0x10, 65_536, 2, 1)

      # same
      refute ExPassword.Argon2.needs_rehash?("$argon2i$m=65536,t=2,p=1$", options)

      # type
      assert ExPassword.Argon2.needs_rehash?("$argon2id$m=65536,t=2,p=1$", options)
      # memory
      assert ExPassword.Argon2.needs_rehash?("$argon2i$m=1048576,t=2,p=1$", options)
      # version
      assert ExPassword.Argon2.needs_rehash?("$argon2i$v=19$m=65536,t=2,p=1$", options)
      # time
      assert ExPassword.Argon2.needs_rehash?("$argon2i$m=65536,t=4,p=2$", options)
      # parallelism
      assert ExPassword.Argon2.needs_rehash?("$argon2i$m=65536,t=2,p=2$", options)
    end

    test "argon2id" do
      options = to_opt(:argon2id, 0x10, 65_536, 2, 1)

      # same
      refute ExPassword.Argon2.needs_rehash?("$argon2id$m=65536,t=2,p=1$", options)

      # type
      assert ExPassword.Argon2.needs_rehash?("$argon2i$m=65536,t=2,p=1$", options)
      # memory
      assert ExPassword.Argon2.needs_rehash?("$argon2id$m=1048576,t=2,p=1$", options)
      # version
      assert ExPassword.Argon2.needs_rehash?("$argon2id$v=19$m=65536,t=2,p=1$", options)
      # time
      assert ExPassword.Argon2.needs_rehash?("$argon2id$m=65536,t=4,p=2$", options)
      # parallelism
      assert ExPassword.Argon2.needs_rehash?("$argon2id$m=65536,t=2,p=2$", options)
    end

    test "ensures error on a non argon2 hash" do
      options = to_opt(:argon2id, 0x10, 65_536, 2, 1)

      assert_raise ArgumentError, fn ->
        ExPassword.Argon2.needs_rehash?("$2y$10$2ABnxzGfyOIgz3woKaJBm.x0akaprqcqVFkkbao/1ullk7lIZEd/2", options)
      end
    end
  end
end
