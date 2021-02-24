defmodule ExPassword.Bcrypt.ExternalTest do
  use ExUnit.Case

  # php -r 'var_dump(password_hash("password", PASSWORD_BCRYPT, ["cost" => 4]));'
  describe "special characters in password are not missinterpreted" do
    test "truncation on space" do
      assert ExPassword.Bcrypt.verify?("arg1 arg2", "$2y$04$mbvOLoQujIwbA4UaGT4l2.DgpaicmXMSerU1qYrqxeCMEgF1qfwfO")
    end

    test "dash is not seen as a command option" do
      assert ExPassword.Bcrypt.verify?("arg1 -r arg2", "$2y$04$ijakqYAugQZeXl4o6hxwGOMBqbmE3AH6VkjEC1XR5SEufHHTpHKZO")
    end

    test "quotes do not fail the command" do
      assert ExPassword.Bcrypt.verify?("abc'def", "$2y$04$NQBNCdf15JP77RIqrjbycusnzuXm8tHrNGGEFRoC3LfdMIjSJhJPi")
      assert ExPassword.Bcrypt.verify?("abc'def'ghi", "$2y$04$ucQvhO0vWieLsF/TmRt04.2nSxnLmzTH3H3qCbtw.puu5MMfJaVW6")
      assert ExPassword.Bcrypt.verify?("abc\"def", "$2y$04$8gQKAe.VaQCS/gL2Hefrq.0WKyiSSqL5MNwjFwqqPk2jydI9Hz9/e")
      assert ExPassword.Bcrypt.verify?("abc\"def\"ghi", "$2y$04$QvDffLdeQZK9/wFYHRBmnejav3PKdEfiW/Ut0bOSTAHL4Le8VrzcC")
    end
  end
end
