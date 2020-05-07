if Mix.env() == :test do
  defmodule ExPassword.MD5 do
    @moduledoc ~S"""
    This module is only used for testing purpose, do **NOT** use it in real world!
    """

    use ExPassword.Algorithm

    def hash(password, _options) do
      password
      |> :erlang.md5()
      |> Base.encode16(case: :lower)
    end

    def needs_rehash?(_hash, _options) do
      false
    end

    def verify?(password, stored_hash) do
      password
      |> hash(%{})
      |> Kernel.==(stored_hash)
    end

    def get_options(_hash) do
      %{algo: "MD5"}
    end

    def valid?(hash) do
      byte_size(hash) == 32
    end
  end
end
