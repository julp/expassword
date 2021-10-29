defmodule ExPassword.VerifyTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.verify?/2" do
    for module <- ExPassword.available_algorithms(), function_exported?(module, :test_set, 0) do
      test "check #{module} hashing" do
        for {password, hash, _salt} <- unquote(module).test_set() do
          assert ExPassword.verify?(password, hash)
        end
      end
    end

    test "check unknown hashing method and/or invalid hash" do
      assert_raise ExPassword.UnidentifiedAlgorithmError, ~R/No suitable algorithm/i, fn ->
        ExPassword.verify?("secret", "not a hash")
      end
    end
  end
end
