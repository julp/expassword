defmodule ExPassword.HashTest do
  use ExUnit.Case
  doctest ExPassword

  describe "ExPassword.hash/3" do
    test "check MD5 hashing" do
      assert "d41d8cd98f00b204e9800998ecf8427e" == ExPassword.hash(ExPassword.MD5, "")
      assert "6896ef955a96e2329e3882c4fe2db95a" == ExPassword.hash(ExPassword.MD5, "Éloïse")
    end

    test "check SHA1 hashing" do
      assert "da39a3ee5e6b4b0d3255bfef95601890afd80709" == ExPassword.hash(ExPassword.SHA1, "")
      assert "f21576ecfe660927e91efb5a11108cdcf2315349" == ExPassword.hash(ExPassword.SHA1, "Éloïse")
    end

    test "check hashing with default algorithm" do
      # TODO ?
    end
  end
end
