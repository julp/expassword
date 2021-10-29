defmodule ExPassword.VerifyAndRehashIfNeededTest do
  use ExUnit.Case
  doctest ExPassword

  defmodule User do
    defstruct ~W[password]a
  end

  describe "ExPassword.verify_and_rehash_if_needed/6" do
    setup do
      [
        options: %{},
        password: "Éloïse",
        algorithm: ExPassword.Test.MD5,
        user: %User{password: "6896ef955a96e2329e3882c4fe2db95a"},
      ]
    end

    test "user is nil", %{password: password, algorithm: algorithm, options: options} do
      {:error, :user_is_nil} = ExPassword.verify_and_rehash_if_needed(nil, "", :password, algorithm, options)
      {:error, :user_is_nil} = ExPassword.verify_and_rehash_if_needed(nil, password, :password, algorithm, options)

      {:error, :user_is_nil} = ExPassword.verify_and_rehash_if_needed(nil, "", :password, ExPassword.Test.SHA1, options)
      {:error, :user_is_nil} = ExPassword.verify_and_rehash_if_needed(nil, password, :password, ExPassword.Test.SHA1, options)
    end

    test "password doesn't match", %{user: user, algorithm: algorithm, options: options} do
      {:error, :password_missmatch} = ExPassword.verify_and_rehash_if_needed(user, "not the password", :password, algorithm, options)
      {:error, :password_missmatch} = ExPassword.verify_and_rehash_if_needed(user, "not the password", :password, ExPassword.Test.SHA1, options)
    end

    test "password match but needs to be updated", %{user: user, password: password, algorithm: algorithm, options: options} do
      {:ok, []} = ExPassword.verify_and_rehash_if_needed(user, password, :password, algorithm, options)

      other_changes = [last_sign_in: DateTime.utc_now()]
      {:ok, ^other_changes} = ExPassword.verify_and_rehash_if_needed(user, password, :password, algorithm, options, other_changes)
    end

    test "password match but doesn't need an update", %{user: user, password: password, options: options} do
      sha1 = "f21576ecfe660927e91efb5a11108cdcf2315349"
      {:ok, [password: ^sha1]} = ExPassword.verify_and_rehash_if_needed(user, password, :password, ExPassword.Test.SHA1, options)

      now = DateTime.utc_now()
      {:ok, changes} = ExPassword.verify_and_rehash_if_needed(user, password, :password, ExPassword.Test.SHA1, options, [last_sign_in: now])
      assert changes[:password] == sha1
      assert changes[:last_sign_in] == now
    end
  end
end
