defmodule ExPassword.GetOptionsTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.get_options/1" do
    test "checks options retrived from the hash" do
      assert {:ok, %{provider: ExPassword.Test.MD5, algo: "MD5"}} == ExPassword.get_options("d41d8cd98f00b204e9800998ecf8427e")
      assert {:ok, %{provider: ExPassword.Test.SHA1, algo: "SHA1"}} == ExPassword.get_options("da39a3ee5e6b4b0d3255bfef95601890afd80709")
      assert {:ok, %{provider: ExPassword.Test.SSHA, algo: "SSHA", salt_length: 4}} == ExPassword.get_options("{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr")
    end
  end
end
