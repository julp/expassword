if Code.ensure_loaded?(ExPassword.Bcrypt.Base) do
  defmodule ExPassword.Bcrypt.ReferenceTest do
    use ExUnit.Case

    @cases [
      {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW", "U*U"},
      {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK", "U*U*"},
      {"$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a", "U*U*U"},
      {"$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui", "0123456789abcdefghijklmnopqrstuvwxyz"
        <> "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" <> "chars after 72 are ignored"},
      {"$2y$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3"},
  # {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.nqd1wy.pTMdcvrRWxyiGL2eMz.2a85.", "\xff\xff\xa3"},
      {"$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e", "\xff\xff\xa3"},
      {"$2y$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3"},
      {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3"},
      {"$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq", "\xa3"},
      {"$2y$05$/OK.fbVrR/bpIqNJ5ianF.o./n25XVfn6oAPaUvHe.Csk4zRfsYPi", "\xff\xa3" <> "34" <> "\xff\xff\xff\xa3" <> "345"},
  # {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.ZC1JEJ8Z4gPfpe1JOr/oyPXTWl9EFd.", "\xff\xa3" <> "34" <> "\xff\xff\xff\xa3" <> "345"},
      {"$2y$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e", "\xff\xa3" <> "345"},
      {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.nRht2l/HRhr6zmCp9vYUvvsqynflf9e", "\xff\xa3" <> "345"},
      {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS", "\xa3" <> "ab"},
      {"$2y$05$/OK.fbVrR/bpIqNJ5ianF.6IflQkJytoRVc1yuaNtHfiuq.FRlSIS", "\xa3" <> "ab"},
      {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.swQOIzjOiJ9GHEPuhEkvqrUyvWhEMx6",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        <> "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        <> "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        <> "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        <> "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        <> "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        <> "chars after 72 are ignored as usual"},
      {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.R9xrDjiycxMbQE2bp.vgqlYpW5wx2yy",
        "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
        <> "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
        <> "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
        <> "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
        <> "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"
        <> "\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55\xaa\x55"},
      {"$2a$05$/OK.fbVrR/bpIqNJ5ianF.9tQZzcJfm3uj2NvJ/n5xkhpqLrMpWCe",
        "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
        <> "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
        <> "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
        <> "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
        <> "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"
        <> "\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff\x55\xaa\xff"},
      {"$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy", ""},
    ]
    test "checks some known hashes" do
      Enum.each(
        @cases,
        fn {hash, password} ->
          result = ExPassword.Bcrypt.Base.hash_nif(password, hash)
          assert hash == result
          assert ExPassword.Bcrypt.Base.verify_nif(password, hash)
          assert ExPassword.Bcrypt.Base.verify_nif(password, result)
        end
      )
    end

    test "salt should be shortened to 128 bits" do
      [
        {
          "test",
          "$2b$10$1234567899123456789012",
          "$2b$10$123456789912345678901u.OtL1A1eGK5wmvBKUDYKvuVKI7h2XBu"
        },
        {
          "U*U*",
          "$2a$05$CCCCCCCCCCCCCCCCCCCCCh",
          "$2a$05$CCCCCCCCCCCCCCCCCCCCCeUQ7VjYZ2hd4bLYZdhuPpZMUpEUJDw1S"
        },
        {
          "U*U*",
          "$2a$05$CCCCCCCCCCCCCCCCCCCCCM",
          "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"
        },
        {
          "U*U*",
          "$2a$05$CCCCCCCCCCCCCCCCCCCCCA",
          "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"
        }
      ]
      |> Enum.each(
        fn {password, salt, hash} ->
          result = ExPassword.Bcrypt.Base.hash_nif(password, salt)
          assert hash == result
  #         assert ExPassword.Bcrypt.Base.verify_nif(password, hash)
  #         assert ExPassword.Bcrypt.Base.verify_nif(password, result)
        end
      )
    end
  end
end
