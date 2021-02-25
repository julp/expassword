defmodule ExPassword.Argon2.VerifyTest do
  use ExUnit.Case

  describe "ExPassword.Argon2.verify?/2" do
    test "ensures only password matches to an argon2 hash" do
      assert true == ExPassword.Argon2.verify?("", "$argon2i$v=19$m=65536,t=4,p=1$VGYvbHU2UmNJRE5GNWdWRw$5UwTisf/0G0SoWgC2XTPhFmvA/qBF3PB13/8GeKVC38")
      assert true == ExPassword.Argon2.verify?("", "$argon2id$v=19$m=65536,t=4,p=1$LlpCOFppNFQuVnlLYWpWcg$WAcH/CdPG41tcwe6DpgNSrCYo1dmKfpwd5WOxsDC9HU")

      assert true == ExPassword.Argon2.verify?("password", "$argon2i$v=19$m=65536,t=4,p=1$QkVwSmdNQnAwY1o5TlZsMg$AuPZJDo9v26VWjUCG0L9bvMonSwbP7qM5BGsXEee8ZE")
      assert true == ExPassword.Argon2.verify?("password", "$argon2id$v=19$m=65536,t=4,p=1$OTM4QldzYkpMZE80TmJWNQ$kFiMuJfI8ysIJ3E8xRwzsyZiJSPrCCkcZ9XjGiduSfU")

      assert false == ExPassword.Argon2.verify?("", "$argon2i$v=19$m=65536,t=4,p=1$QkVwSmdNQnAwY1o5TlZsMg$AuPZJDo9v26VWjUCG0L9bvMonSwbP7qM5BGsXEee8ZE")
      assert false == ExPassword.Argon2.verify?("", "$argon2id$v=19$m=65536,t=4,p=1$OTM4QldzYkpMZE80TmJWNQ$kFiMuJfI8ysIJ3E8xRwzsyZiJSPrCCkcZ9XjGiduSfU")

      if Code.ensure_loaded?(ExPassword.Argon2.Base) do
        assert true == ExPassword.Argon2.verify?("password\x00", "$argon2i$v=19$m=65536,t=4,p=1$LnZlVExxV3J2Z21XaVEzWA$OTNjGhhSqY0Mz7J/M9shOpm68YIbI0o1osQ/DLYLGTE")
        assert true == ExPassword.Argon2.verify?("password\x00", "$argon2id$v=19$m=65536,t=4,p=1$Rk9TcGl5eDNveUZGb2FKMw$A1rRtokCQjmzApNyZQj1dJNnwEgJcIfRsAagV39WNIc")
      end

      assert false == ExPassword.Argon2.verify?("password", "$argon2i$v=19$m=65536,t=4,p=1$LnZlVExxV3J2Z21XaVEzWA$OTNjGhhSqY0Mz7J/M9shOpm68YIbI0o1osQ/DLYLGTE")
      assert false == ExPassword.Argon2.verify?("password", "$argon2id$v=19$m=65536,t=4,p=1$Rk9TcGl5eDNveUZGb2FKMw$A1rRtokCQjmzApNyZQj1dJNnwEgJcIfRsAagV39WNIc")
    end
  end
end
