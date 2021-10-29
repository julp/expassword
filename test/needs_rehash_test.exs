defmodule ExPassword.NeedsRehashTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.needs_rehash?/3" do
    test "returns true if algorithm is not the same" do
      # algo = MD5 ; hash = SHA1
      assert ExPassword.needs_rehash?(ExPassword.Test.MD5, "da39a3ee5e6b4b0d3255bfef95601890afd80709", %{})
      # algo = SHA1 ; hash = MD5
      assert ExPassword.needs_rehash?(ExPassword.Test.SHA1, "d41d8cd98f00b204e9800998ecf8427e", %{})
    end

    @algo ExPassword.Test.SSHA
    # "{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr" = "testing123" with 4 bytes of salt
    @hash "{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr"
    test "returns true only if salt is higher for SSHA" do
      refute ExPassword.needs_rehash?(@algo, @hash, %{salt_length: 3})
      refute ExPassword.needs_rehash?(@algo, @hash, %{salt_length: 4})
      assert ExPassword.needs_rehash?(@algo, @hash, %{salt_length: 5})
    end
  end
end
