defmodule ExPassword.HashTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.hash/3" do
    for module <- ExPassword.available_algorithms(), function_exported?(module, :test_set, 0) do
      test "check #{module} hashing" do
        for {password, hash, salt} <- unquote(module).test_set() do
          assert hash == ExPassword.hash(unquote(module), password, %{salt: salt})
        end
      end
    end
  end
end
