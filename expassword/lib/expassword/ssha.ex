if Mix.env() == :test do
  defmodule ExPassword.SSHA do
    @moduledoc ~S"""
    This module is only used for testing purpose, do **NOT** use it in real world!
    """

    use ExPassword.Algorithm

    @prefix "{SSHA}"
    @default_salt_len 16
    @salt_length_option :salt_length
    defp fetch_salt_len(options) do
      Map.get(options, @salt_length_option, @default_salt_len)
    end

    def hash(password, options) do
      salt = options
      |> fetch_salt_len()
      |> :crypto.strong_rand_bytes()

      @prefix <> :crypto.hash(:sha, password <> salt)
      |> Kernel.<>(salt)
      |> Base.encode64(case: :lower)
    end

    def needs_rehash?(<<@prefix, hash::binary>>, options) do
      <<_digest::bytes-size(20), salt::binary>> = Base.decode64!(hash)
      fetch_salt_len(options) > byte_size(salt)
    end

    def verify?(password, <<@prefix, hash::binary>>) do
      <<digest::bytes-size(20), salt::binary>> = Base.decode64!(hash)
      :crypto.hash(:sha, password <> salt) == digest
    end

    def get_options(<<@prefix, hash::binary>>) do
      <<_digest::bytes-size(20), salt::binary>> = Base.decode64!(hash)
      %{@salt_length_option => byte_size(salt), algo: "SSHA"}
    end

    def valid?(<<@prefix, _rest::binary>>), do: true
    def valid?(_), do: false
  end
end
