defmodule ExPassword.FindAlgorithmTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.find_algorithm/1" do
    test "find a supported algorithm" do
      # MD5("")
      assert ExPassword.Test.MD5 == ExPassword.find_algorithm("d41d8cd98f00b204e9800998ecf8427e")
      # SHA1("")
      assert ExPassword.Test.SHA1 == ExPassword.find_algorithm("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    end

    test "returns nil on non-supported algorithm" do
      # SHA256("")
      assert is_nil(ExPassword.find_algorithm("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))
    end
  end
end
