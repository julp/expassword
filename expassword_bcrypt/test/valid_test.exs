defmodule ExPassword.Bcrypt.ValidTest do
  use ExUnit.Case

  describe "ExPassword.Bcrypt.valid?/2" do
    test "ensures a bcrypt hash is valid" do
      assert true == ExPassword.Bcrypt.valid?("$2y$04$mbvOLoQujIwbA4UaGT4l2.DgpaicmXMSerU1qYrqxeCMEgF1qfwfO")
      assert true == ExPassword.Bcrypt.valid?("$2a$04$mbvOLoQujIwbA4UaGT4l2.DgpaicmXMSerU1qYrqxeCMEgF1qfwfO")
      assert true == ExPassword.Bcrypt.valid?("$2b$04$mbvOLoQujIwbA4UaGT4l2.DgpaicmXMSerU1qYrqxeCMEgF1qfwfO")
    end

    test "ensures everything else is invalid" do
      assert false == ExPassword.Bcrypt.valid?("$2c$04$mbvOLoQujIwbA4UaGT4l2.DgpaicmXMSerU1qYrqxeCMEgF1qfwfO")
      assert false == ExPassword.Bcrypt.valid?("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ")
      assert false == ExPassword.Bcrypt.valid?("$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")
      assert false == ExPassword.Bcrypt.valid?("$argon2d$v=19$m=1024,t=16,p=4$c2FsdDEyM3NhbHQxMjM$2dVtFVPCezhvjtyu2PaeXOeBR+RUZ6SqhtD/+QF4F1o")
      assert false == ExPassword.Bcrypt.valid?("d41d8cd98f00b204e9800998ecf8427e")
      assert false == ExPassword.Bcrypt.valid?("da39a3ee5e6b4b0d3255bfef95601890afd80709")
    end
  end
end
