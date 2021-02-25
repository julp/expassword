defmodule ExPassword.Bcrypt.HashTest do
  use ExUnit.Case

  describe "ExPassword.Bcrypt.hash/2" do
    test "ensures a hash is produced with valid options" do
      assert <<"$2b$04$", _rest::binary-size(53)>> = ExPassword.Bcrypt.hash("", %{cost: 4})
      assert <<"$2b$06$", _rest::binary-size(53)>> = ExPassword.Bcrypt.hash("", %{cost: 6})
      assert <<"$2b$10$", _rest::binary-size(53)>> = ExPassword.Bcrypt.hash("", %{cost: 10})
    end

    test "raises when options are invalid" do
      assert_raise ArgumentError, fn ->
        ExPassword.Bcrypt.hash("", %{cost: 2})
      end
      assert_raise ArgumentError, fn ->
        ExPassword.Bcrypt.hash("", %{cost: nil})
      end
      assert_raise ArgumentError, fn ->
        ExPassword.Bcrypt.hash("", %{})
      end
    end
  end
end
