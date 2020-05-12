defmodule ExPassword.Test.MD5 do
  @moduledoc ~S"""
  This module is only used for testing purpose, do **NOT** use it in real world!
  """

  use ExPassword.Test.Set

  @impl ExPassword.Test.Set
  def test_set do
    [
      {"", "d41d8cd98f00b204e9800998ecf8427e", nil},
      {"Éloïse", "6896ef955a96e2329e3882c4fe2db95a", nil},
    ]
  end

  use ExPassword.Algorithm

  @impl ExPassword.Algorithm
  def hash(password, _options) do
    password
    |> :erlang.md5()
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
    {:ok, %{algo: "MD5"}}
  end

  @impl ExPassword.Algorithm
  def valid?(hash) do
    byte_size(hash) == 32
  end
end
