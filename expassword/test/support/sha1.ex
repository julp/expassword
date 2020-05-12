defmodule ExPassword.Test.SHA1 do
  @moduledoc ~S"""
  This module is only used for testing purpose, do **NOT** use it in real world!
  """

  use ExPassword.Test.Set

  @impl ExPassword.Test.Set
  def test_set do
    [
      {"", "da39a3ee5e6b4b0d3255bfef95601890afd80709", nil},
      {"Éloïse", "f21576ecfe660927e91efb5a11108cdcf2315349", nil},
    ]
  end

  use ExPassword.Algorithm

  @impl ExPassword.Algorithm
  def hash(password, _options) do
    :crypto.hash(:sha, password)
    |> Base.encode16(case: :lower)
  end

  @impl ExPassword.Algorithm
  def needs_rehash?(_hash, _options) do
    false
  end

  @impl ExPassword.Algorithm
  def verify?(password, stored_hash) do
    password
    |> hash(%{})
    |> Kernel.==(stored_hash)
  end

  @impl ExPassword.Algorithm
  def get_options(_hash) do
    {:ok, %{algo: "SHA1"}}
  end

  @impl ExPassword.Algorithm
  def valid?(hash) do
    byte_size(hash) == 40
  end
end
