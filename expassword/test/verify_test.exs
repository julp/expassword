defmodule ExPassword.VerifyTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.verify?/2" do
    test "check MD5 hashing" do
      assert ExPassword.verify?("", "d41d8cd98f00b204e9800998ecf8427e")
      assert ExPassword.verify?("Éloïse", "6896ef955a96e2329e3882c4fe2db95a")
    end

    test "check SHA1 hashing" do
      assert ExPassword.verify?("", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
      assert ExPassword.verify?("Éloïse", "f21576ecfe660927e91efb5a11108cdcf2315349")
    end

    test "check SSHA hashing" do
      assert ExPassword.verify?("testing123", "{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr")
    end

    test "check unknown hashing method and/or invalid hash" do
      assert ExPassword.verify?("secret", "not a hash")
    end
  end
end
