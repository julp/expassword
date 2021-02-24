if Code.ensure_loaded?(ExPassword.Argon2.Base) do
  defmodule ExPassword.Argon2.ReferenceTest do
    use ExUnit.Case
    use Bitwise

    defp strlen(_x), do: nil # unused

    defp argon2_verify(hash, password, _password_len, _type) do
      ExPassword.Argon2.verify?(password, hash)
    end

    defp hashtest(v, t, m, p, password, salt, hexref, mcfref, type) do
      result = ExPassword.Argon2.Base.hash_nif(password, salt, %{type: type, version: v, memory_cost: 1 <<< m, threads: p, time_cost: t})
      result = if v == 0x10 do
        String.replace(result, "$v=16$", "$")
      else
        result
      end
      assert mcfref == result
      assert ExPassword.Argon2.verify?(password, mcfref)
      assert ExPassword.Argon2.verify?(password, result)
      assert Base.decode64!(Enum.at(String.split(mcfref, "$"), -1), padding: false) == Base.decode16!(hexref, case: :lower)
    end

    defp argon2_hash(t_cost, m_cost, parallelism, pwd, _pwdlen, salt, _saltlen, type, version) do
      ExPassword.Argon2.Base.hash_nif(pwd, salt, %{type: type, version: version, memory_cost: 1 <<< m_cost, threads: parallelism, time_cost: t_cost})
    end

    test "argon2i with version 0x10" do
      version = 0x10
      hashtest(version, 2, 16, 1, "password", "somesalt",
        "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
        "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ", :argon2i)
      hashtest(version, 2, 20, 1, "password", "somesalt",
        "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
        "$argon2i$m=1048576,t=2,p=1$c29tZXNhbHQ" <>
        "$lpDsVdKNPtMlYvLnPqYrArAYdXZDoq5ueVKEWd6BBuk", :argon2i)
      hashtest(version, 2, 18, 1, "password", "somesalt",
        "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
        "$argon2i$m=262144,t=2,p=1$c29tZXNhbHQ" <>
        "$Pmiaqj0op3zyvHKlGsUxZnYXURgvHuKS4/Z3p9pMJGc", :argon2i)
      hashtest(version, 2, 8, 1, "password", "somesalt",
        "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
        "$argon2i$m=256,t=2,p=1$c29tZXNhbHQ" <>
        "$/U3YPXYsSb3q9XxHvc0MLxur+GP960kN9j7emXX8zwY", :argon2i)
      hashtest(version, 2, 8, 2, "password", "somesalt",
        "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb",
        "$argon2i$m=256,t=2,p=2$c29tZXNhbHQ" <>
        "$tsEVYKap1h6scGt5ovl9aLRGOqOth+AMB+KwHpDFZPs", :argon2i)
      hashtest(version, 1, 16, 1, "password", "somesalt",
        "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2",
        "$argon2i$m=65536,t=1,p=1$c29tZXNhbHQ" <>
        "$gWMFUrjzsfSM2xmSxMZ4ZD1JCytetP9sSzQ4tWIXJLI", :argon2i)
      hashtest(version, 4, 16, 1, "password", "somesalt",
        "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b",
        "$argon2i$m=65536,t=4,p=1$c29tZXNhbHQ" <>
        "$8hLwFhXm6110c03D70Ct4tUdBSRo2MaUQKOh8sHChHs", :argon2i)
      hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
        "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3",
        "$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$6ckCB0tnVFMaOgvlGeW69ASzDOabPwGsO/ISKZYBCaM", :argon2i)
      hashtest(version, 2, 16, 1, "password", "diffsalt",
        "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497",
        "$argon2i$m=65536,t=2,p=1$ZGlmZnNhbHQ" <>
        "$eaEDuQ/orvhXDLMfyLIiWXeJFvgza3vaw4kladTxxJc", :argon2i)
    end

    test "error states tests for argon2i with version 0x10" do
      # Handle an invalid encoding correctly (it is missing a $)
      assert_raise ArgumentError, ~R/Decoding failed/i, fn ->
        argon2_verify("$argon2i$m=65536,t=2,p=1c29tZXNhbHQ" <>
          "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
          "password", strlen("password"), :argon2i)
      end
      # Handle an invalid encoding correctly (it is missing a $)
      assert_raise ArgumentError, ~R/Decoding failed/i, fn ->
        argon2_verify("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" <>
          "9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
          "password", strlen("password"), :argon2i)
      end
      # Handle an invalid encoding correctly (salt is too short) */
      assert_raise ArgumentError, ~R/Salt is too short/i, fn ->
        argon2_verify("$argon2i$m=65536,t=2,p=1$" <>
          "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
          "password", strlen("password"), :argon2i)
      end
      # Handle an mismatching hash (the encoded password is "passwore") */
      refute argon2_verify("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo",
        "password", strlen("password"), :argon2i)
    end

    test "argon2i with version 0x13" do
      version = 0x13
      hashtest(version, 2, 16, 1, "password", "somesalt",
        "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA", :argon2i)
      hashtest(version, 2, 20, 1, "password", "somesalt",
        "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41",
        "$argon2i$v=19$m=1048576,t=2,p=1$c29tZXNhbHQ" <>
        "$0Vh6ygkiw7XWqD7asxvuPE667zQu1hJ6VdGbI1GtH0E", :argon2i)
      hashtest(version, 2, 18, 1, "password", "somesalt",
        "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb",
        "$argon2i$v=19$m=262144,t=2,p=1$c29tZXNhbHQ" <>
        "$KW266AuAfNzqrUSudBtQbxTbCVkmexg7EY+bJCKbx8s", :argon2i)
      hashtest(version, 2, 8, 1, "password", "somesalt",
        "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f",
        "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ" <>
        "$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8", :argon2i)
      hashtest(version, 2, 8, 2, "password", "somesalt",
        "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61",
        "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ" <>
        "$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E", :argon2i)
      hashtest(version, 1, 16, 1, "password", "somesalt",
        "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf",
        "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ" <>
        "$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8", :argon2i)
      hashtest(version, 4, 16, 1, "password", "somesalt",
        "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b",
        "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ" <>
        "$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls", :argon2i)
      hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
        "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee",
        "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4", :argon2i)
      hashtest(version, 2, 16, 1, "password", "diffsalt",
        "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271",
        "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ" <>
        "$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE", :argon2i)
    end

    test "error states tests for argon2i with version 0x13" do
      # Handle an invalid encoding correctly (it is missing a $)
      assert_raise ArgumentError, ~R/Decoding failed/i, fn ->
        argon2_verify("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ" <>
          "$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
          "password", strlen("password"), :argon2i)
      end
      # Handle an invalid encoding correctly (it is missing a $)
      assert_raise ArgumentError, ~R/Decoding failed/i, fn ->
        argon2_verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" <>
          "wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA",
          "password", strlen("password"), :argon2i)
      end
      # Handle an invalid encoding correctly (salt is too short) */
      assert_raise ArgumentError, ~R/Salt is too short/i, fn ->
        argon2_verify("$argon2i$v=19$m=65536,t=2,p=1$" <>
          "$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ",
          "password", strlen("password"), :argon2i)
      end
      # Handle an mismatching hash (the encoded password is "passwore")
      refute argon2_verify("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM",
        "password", strlen("password"), :argon2i)
    end

    test "argon2id with version 0x13" do
      version = 0x13
      hashtest(version, 2, 16, 1, "password", "somesalt",
        "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc", :argon2id)
      hashtest(version, 2, 18, 1, "password", "somesalt",
        "78fe1ec91fb3aa5657d72e710854e4c3d9b9198c742f9616c2f085bed95b2e8c",
        "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ" <>
        "$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow", :argon2id)
      hashtest(version, 2, 8, 1, "password", "somesalt",
        "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
        "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ" <>
        "$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4", :argon2id)
      hashtest(version, 2, 8, 2, "password", "somesalt",
        "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
        "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ" <>
        "$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc", :argon2id)
      hashtest(version, 1, 16, 1, "password", "somesalt",
        "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
        "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ" <>
        "$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg", :argon2id)
      hashtest(version, 4, 16, 1, "password", "somesalt",
        "9025d48e68ef7395cca9079da4c4ec3affb3c8911fe4f86d1a2520856f63172c",
        "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ" <>
        "$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw", :argon2id)
      hashtest(version, 2, 16, 1, "differentpassword", "somesalt",
        "0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde",
        "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ" <>
        "$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94", :argon2id)
      hashtest(version, 2, 16, 1, "password", "diffsalt",
        "bdf32b05ccc42eb15d58fd19b1f856b113da1e9a5874fdcc544308565aa8141c",
        "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ" <>
        "$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw", :argon2id)
    end

    test "Common error state tests" do
      version = 0x13
      assert_raise ArgumentError, ~R/Memory cost is too small/i, fn ->
        argon2_hash(2, 1, 1, "password", strlen("password"),
          "diffsalt", strlen("diffsalt"),
          :argon2id, version)
      end
      assert_raise ArgumentError, ~R/Salt is too short/i, fn ->
        argon2_hash(2, 12, 1, "password", strlen("password"), "s", 1,
          :argon2id, version)
      end
    end
  end
end
