defmodule ExPassword.Bcrypt do
  @moduledoc ~S"""
  This module implements the `ExPassword.Algorithm` behaviour to add support for Bcrypt hashing algorithms.

  Except for specific details about proper options and deeper details, you might looking for `ExPassword`'s
  documentation.
  """

  use ExPassword.Algorithm

  alias ExPassword.Bcrypt.Base

  @default_salt_length 16

  defguardp is_valid_cost(cost) when is_integer(cost) and cost >= 4 and cost <= 31

  defp raise_invalid_options(options) do
    raise ArgumentError, """
    Expected options parameter to have the following key:

    - cost: an integer in the [4;31] range

    Instead, got: #{inspect(options)}
    """
  end

  @doc """
  Computes the hash for *password*. A salt of #{@default_salt_length} bytes is randomly generated
  and prepended to *password* before hashing.

  Valid options are:

    * cost: the algorithmic cost. It defines the number of iterations as a power of two (2^*cost*) so
      higher is the cost longer it takes to compute it (and consequently brute force it)

  An `ArgumentError` will be raised if one of the options above is invalid or if an internal error occurs.
  """
  # NOTE: version option is voluntarily not documented
  @impl ExPassword.Algorithm
  def hash(password, options = %{cost: cost})
    when is_valid_cost(cost) # and map_size(options) == 1
  do
    salt =
      @default_salt_length
      |> :crypto.strong_rand_bytes()
      |> Base.generate_salt_nif(options)
    Base.hash_nif(password, salt)
  end

  def hash(_password, options) do
    raise_invalid_options(options)
  end

  @doc ~S"""
  Checks that a password matches the given bcrypt hash

  An `ArgumentError` will be raised if the hash is somehow invalid or if an internal error occurs.
  """
  @impl ExPassword.Algorithm
  def verify?(password, hash) do
    Base.verify_nif(password, hash)
  end

  @doc ~S"""
  Extracts informations from a given bcrypt hash (the options used to generate it in the first place)

  Returns `{:error, :invalid}` if *hash* is not a valid bcrypt hash else `{:ok, map}` where map is a Map which
  contains all the parameters that permitted to compute this hash.

      iex> ExPassword.Bcrypt.get_options("$2a$04$5DCebwootqWMCp59ISrMJ.l4WvgHIVg17ZawDIrDM2IjlE64GDNQS")
      {:ok, %{cost: 4}}
  """
  @impl ExPassword.Algorithm
  def get_options(hash) do
    Base.get_options_nif(hash)
  end

  @doc ~S"""
  Compares the options used to generate *hash* to *options* and returns `true` if they differ, which
  means you should rehash the password to update its hash.
  """
  @impl ExPassword.Algorithm
  def needs_rehash?(hash, options = %{cost: cost})
    when is_valid_cost(cost) # and map_size(options) == 1
  do
    Base.needs_rehash_nif(hash, options)
  end

  def needs_rehash?(_hash, options) do
    raise_invalid_options(options)
  end

  @doc ~S"""
  Returns `true` if *hash* seems to be a Bcrypt hash.

  This function is intended to quickly identify the algorithm which produces the given hash.
  It does not perform extended checks like `get_options/1` nor `needs_rehash?/2` nor `verify?/2` do.
  """
  @impl ExPassword.Algorithm
  def valid?(hash) do
    Base.valid_nif(hash)
  end
end
