defmodule ExPassword.Argon2 do
  @moduledoc ~S"""
  TODO
  """

  use ExPassword.Algorithm

  alias ExPassword.Argon2.Base

  @doc ~S"""
  TODO
  """
  @impl ExPassword.Algorithm
  def hash(password, options) do
    Base.hash_nif(password, Map.get(options, :salt, :crypto.strong_rand_bytes(16)), options)
  end

  @doc ~S"""
  TODO
  """
  @impl ExPassword.Algorithm
  def verify?(hash, password) do
    Base.verify_nif(hash, password)
  end

  @doc ~S"""
  TODO
  """
  @impl ExPassword.Algorithm
  def get_options(hash) do
    Base.get_options_nif(hash)
  end

  @doc ~S"""
  TODO
  """
  @impl ExPassword.Algorithm
  def needs_rehash?(hash, options) do
    Base.needs_rehash_nif(hash, options)
  end

  @doc ~S"""
  TODO
  """
  @impl ExPassword.Algorithm
  def valid?(hash) do
    Base.valid_nif(hash)
  end
end
