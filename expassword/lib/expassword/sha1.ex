if Mix.env() == :test do
  defmodule ExPassword.SHA1 do
    @moduledoc ~S"""
    This module is only used for testing purpose, do **NOT** use it in real world!
    """

    use ExPassword.Algorithm

    def hash(password, _options) do
      :crypto.hash(:sha, password)
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
      %{algo: "SHA1"}
    end

    def valid?(hash) do
      byte_size(hash) == 40
    end
  end
end
