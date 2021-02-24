defmodule ExPassword.Argon2 do
  @moduledoc ~S"""
  This module implements the `ExPassword.Algorithm` behaviour to add support for Argon2 hashing algorithms.

  Except for specific details about proper options and deeper details, you might looking for `ExPassword`'s
  documentation.
  """

  use ExPassword.Algorithm

  alias ExPassword.Argon2.Base

  @default_salt_length 16

  defguardp is_valid_type(type) when type in ~W[argon2i argon2id]a
  defguardp is_valid_threads(threads) when is_integer(threads) and threads >= 1
  defguardp is_valid_time_cost(time_cost) when is_integer(time_cost) and time_cost >= 1
  defguardp is_valid_memory_cost(memory_cost) when is_integer(memory_cost) and memory_cost >= 16

  defp raise_invalid_options(options) do
    raise ArgumentError, """
    Expected options parameter to have the following keys:

    - type: the atom :argon2i or :argon2id
    - threads: an integer >= 1
    - time_cost: an integer >= 1
    - memory_cost: an integer >= 16
    - version (optional): the integer 16 or 19

    Instead, got: #{inspect(options)}
    """
  end

  @doc """
  Computes the hash for *password*. A salt of #{@default_salt_length} bytes is randomly generated
  and prepended to *password* before hashing.

  Valid options are:

    * threads (also called parallelism): number of threads to use for computing the Argon2 hash
    * time_cost (in seconds): maximum amount of time it may take to compute the Argon2 hash
    * memory_cost (in kibibytes): maximum amount of memory that may be used to compute the Argon2 hash
    * type:
      + `:argon2i`: use the Argon2i hashing algorithm
      + `:argon2id` (default and recommended): use the Argon2id hashing algorithm

  An `ArgumentError` will be raised if one of the options above is invalid or if an internal error occurs.
  """
  # NOTE: version option is voluntarily not documented
  @impl ExPassword.Algorithm
  def hash(password, options = %{type: type, threads: threads, time_cost: time_cost, memory_cost: memory_cost})
    when is_valid_type(type) and is_valid_threads(threads) and is_valid_time_cost(time_cost) and is_valid_memory_cost(memory_cost)
  do
    Base.hash_nif(password, :crypto.strong_rand_bytes(@default_salt_length), options)
  end

  def hash(_password, options) do
    raise_invalid_options(options)
  end

  @doc ~S"""
  Checks that a password matches the given argon2 hash

  An `ArgumentError` will be raised if the hash is somehow invalid or if an internal error occurs.
  """
  @impl ExPassword.Algorithm
  def verify?(password, hash) do
    Base.verify_nif(password, hash)
  end

  @doc ~S"""
  Extracts informations from a given argon2 hash (the options used to generate it in the first place)

  Returns `{:error, :invalid}` if *hash* is not a valid argon2 hash else `{:ok, map}` where map is a Map which
  contains all the parameters that permitted to compute this hash.

      iex> ExPassword.Argon2.get_options("$argon2i$v=19$m=65536,t=4,p=2$<truncated>")
      {:ok, %{memory_cost: 65536, threads: 2, time_cost: 4, type: :argon2i, version: 19}}
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
  def needs_rehash?(hash, options = %{type: type, threads: threads, time_cost: time_cost, memory_cost: memory_cost})
    when is_valid_type(type) and is_valid_threads(threads) and is_valid_time_cost(time_cost) and is_valid_memory_cost(memory_cost)
  do
    Base.needs_rehash_nif(hash, options)
  end

  def needs_rehash?(_hash, options) do
    raise_invalid_options(options)
  end

  @doc ~S"""
  Returns `true` if *hash* seems to be an Argon2 hash.

  This function is intended to quickly identify the algorithm which produces the given hash.
  It does not perform extended checks like `get_options/1` nor `needs_rehash?/2` nor `verify?/2` do.
  """
  @impl ExPassword.Algorithm
  def valid?(hash) do
    Base.valid_nif(hash)
  end
end
