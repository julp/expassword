defmodule ExPassword.Argon2.ValidTest do
  use ExUnit.Case

  describe "ExPassword.Argon2.valid?/2" do
    test "ensures an argon2i hash is valid" do
      assert true == ExPassword.Argon2.valid?("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ")
      assert true == ExPassword.Argon2.valid?("$argon2i$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ")
      assert true == ExPassword.Argon2.valid?("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")
    end

    test "ensures an argon2id hash is valid" do
      assert true == ExPassword.Argon2.valid?("$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")
      assert true == ExPassword.Argon2.valid?("$argon2id$v=16$m=65536,t=2,p=4$HvNaNwCf4Bn55RLuR8uu1g==$e7ZgRsnRbZaFkXs2ogmbD5dt/mF5B0IAvOTYDr0ebZI=")
      assert true == ExPassword.Argon2.valid?("$argon2id$m=65536,t=2,p=4$HvNaNwCf4Bn55RLuR8uu1g==$e7ZgRsnRbZaFkXs2ogmbD5dt/mF5B0IAvOTYDr0ebZI=")
    end

    test "ensures everything else is invalid" do
      assert false == ExPassword.Argon2.valid?("$argon2d$v=19$m=1024,t=16,p=4$c2FsdDEyM3NhbHQxMjM$2dVtFVPCezhvjtyu2PaeXOeBR+RUZ6SqhtD/+QF4F1o")
      assert false == ExPassword.Argon2.valid?("d41d8cd98f00b204e9800998ecf8427e")
      assert false == ExPassword.Argon2.valid?("da39a3ee5e6b4b0d3255bfef95601890afd80709")
      assert false == ExPassword.Argon2.valid?("$2y$10$4oVYiqVa5CvWunP4R9N.2OXOgP5fntE9pTRuw7CzNILHr9GNtbtKO")
    end
  end
end
