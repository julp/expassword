defmodule ExPassword.Argon2.GetOptionsTest do
  use ExUnit.Case

  describe "ExPassword.Argon2.get_options/1" do
    test "ensures options from a valid argon2i hash are successfully extracted" do
      assert {:ok, %{type: :argon2i, memory_cost: 1_048_576, version: 0x10, threads: 1, time_cost: 2}} == ExPassword.Argon2.get_options("$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk")
      assert {:ok, %{type: :argon2i, memory_cost: 65_536, version: 0x13, threads: 2, time_cost: 4}} == ExPassword.Argon2.get_options("$argon2i$v=19$m=65536,t=4,p=2$MS4yVjlVck5ZVlcwQlV6WA$JRgNzvz0ivV/3BIlq6DZxE3Vnhrfl5YX6Lpxym0ucUw")
    end

    test "ensures options from a valid argon2id hash are successfully extracted" do
      assert {:ok, %{type: :argon2id, memory_cost: 256, version: 0x13, threads: 1, time_cost: 2}} == ExPassword.Argon2.get_options("$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4")
    end

    test "ensures error on a non argon2 hash" do
      assert {:error, :invalid} == ExPassword.Argon2.get_options("$2y$10$2ABnxzGfyOIgz3woKaJBm.x0akaprqcqVFkkbao/1ullk7lIZEd/2")
    end

    test "ensures error on an invalid argon2id hash" do
      assert {:error, :invalid} == ExPassword.Argon2.get_options("$argon2id$v=19$m=256,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4")
    end
  end
end
