defmodule ExPassword.Bcrypt.GetOptionsTest do
  use ExUnit.Case

  describe "ExPassword.Bcrypt.get_options/1" do
    test "ensures options from a valid bcrypt hash are successfully extracted" do
      assert {:ok, %{cost: 5}} == ExPassword.Bcrypt.get_options("$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS")
      assert {:ok, %{cost: 10}} == ExPassword.Bcrypt.get_options("$2y$10$jau8CKRHbXcSGFi5ehYhz.zKoOdPiEQO4GQ7S0./h6th46tRyHEd2")
    end

    test "ensures error on a non bcrypt hash" do
      assert {:error, :invalid} == ExPassword.Bcrypt.get_options("25169a6624cdeb2e5d97dd96d0977b2b")
      assert {:error, :invalid} == ExPassword.Bcrypt.get_options("511453fe3c5f592d0a048baa187a6fc60609faad")
      assert {:error, :invalid} == ExPassword.Bcrypt.get_options("$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk")
    end

    test "ensures error on an invalid bcrypt hash" do
      assert {:error, :invalid} == ExPassword.Bcrypt.get_options("$2c$10$0Foz280fKzIYqnK36x33fOFpUcrKsRrHH1v4guaN8lbLZFkAwhkc6")
    end
  end
end
