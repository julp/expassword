defmodule ExPassword.Bcrypt.NeedsRehashTest do
  use ExUnit.Case

  defp to_opt(cost) do
    %{cost: cost}
  end

  describe "ExPassword.Bcrypt.needs_rehash?/2" do
    test "ensures return value depends on cost" do
      options = to_opt(10)

      # same
      refute ExPassword.Bcrypt.needs_rehash?("$2y$10$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", options)

      # lower cost
      assert ExPassword.Bcrypt.needs_rehash?("$2y$09$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", options)
      # higher cost
      assert ExPassword.Bcrypt.needs_rehash?("$2y$11$XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", options)
    end

    test "ensures error on a non bcrypt hash" do
      options = to_opt(11)

      assert_raise ArgumentError, fn ->
        ExPassword.Bcrypt.needs_rehash?("$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk", options)
      end
    end
  end
end
