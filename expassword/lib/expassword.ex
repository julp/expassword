defmodule ExPassword do
  @moduledoc """
  Documentation for ExPassword.
  """

  @type algorithm :: module

  @known_algorithms [
    # implies :expassword_bcrypt listed as dependency in your mix.exs
    ExPassword.Bcrypt,
    # implies :expassword_argon2 listed as dependency in your mix.exs
    ExPassword.Argon2,
    # <testing only>
    ExPassword.Test.MD5,
    ExPassword.Test.SHA1,
    ExPassword.Test.SSHA,
    # </testing only>
  ]
  @available_algorithms for algorithm <- @known_algorithms, {:module, algorithm} == Code.ensure_compiled(algorithm), do: algorithm

  @doc false
  @spec find_algorithm(hash :: ExPassword.Algorithm.hash) :: algorithm | nil
  def find_algorithm(hash) do
    @available_algorithms
    |> Enum.find(nil, &(&1.valid?(hash)))
  end

  @doc ~S"""
  Returns the list of the modules that currently (at compile time) are enabled and provide support to ExPassword for a hashing method
  """
  @spec available_algorithms() :: [algorithm]
  def available_algorithms do
    @available_algorithms
  end

  @doc ~S"""
  TODO (x)
  """
  @spec x(user :: struct | nil, password :: ExPassword.Algorithm.password, field :: atom, algorithm :: algorithm, options :: ExPassword.Algorithm.options) :: {:ok, ExPassword.Algorithm.hash | nil} | {:error, :user_is_nil | :password_missmatch} | no_return
  def x(user, password, field \\ :encrypted_password, algorithm, options)

  def x(nil, password, field, algorithm, options = %{})
    when is_binary(password) and is_atom(field) and is_atom(algorithm)
  do
    ExPassword.hash(algorithm, password, options)
    {:error, :user_is_nil}
  end

  def x(user = %_{}, password, field, algorithm, options = %{})
    when is_binary(password) and is_atom(field) and is_atom(algorithm)
  do
    hash = Map.fetch!(user, field)
    case ExPassword.verify?(password, hash) do
      true ->
        change = if ExPassword.needs_rehash?(algorithm, hash, options) do # TODO
          [{field, ExPassword.hash(algorithm, password, options)}]
        else
          nil
        end
        {:ok, change}
      false ->
        {:error, :password_missmatch}
    end
  end

  @doc ~S"""
  Hashes *password* using the given *algorithm* and *options*.

  *algorithm* has to be a module present in `available_algorithms/0`.
  """
  @spec hash(algorithm :: algorithm, password :: ExPassword.Algorithm.password, options :: ExPassword.Algorithm.options) :: ExPassword.Algorithm.hash | no_return
  def hash(algorithm, password, options = %{})
    when algorithm in @available_algorithms and is_binary(password)
  do
    algorithm.hash(password, options)
  end

  @doc ~S"""
  Checks if *password* matches the given *hash*

  Raises a `ExPassword.UnidentifiedAlgorithmError` error if any of `available_algorithms/0` recognizes *hash*
  """
  @spec verify?(password :: ExPassword.Algorithm.password, hash :: ExPassword.Algorithm.hash) :: boolean | no_return
  def verify?(password, hash)
    when is_binary(password) and is_binary(hash)
  do
    case find_algorithm(hash) do
      nil ->
        raise ExPassword.UnidentifiedAlgorithmError, hash: hash
      algorithm ->
        algorithm.verify?(password, hash)
    end
  end

  @doc ~S"""
  Returns `true` if the *hash* has not been issued by *algorithm* or *options* are different from the one used to generate *hash*
  """
  @spec needs_rehash?(algorithm :: algorithm, hash :: ExPassword.Algorithm.hash, options :: ExPassword.Algorithm.options) :: boolean | no_return
  def needs_rehash?(algorithm, hash, options = %{})
    when algorithm in @available_algorithms and is_binary(hash)
  do
    case find_algorithm(hash) do
      ^algorithm ->
        algorithm.needs_rehash?(hash, options)
      _ ->
        true
    end
  end

  @doc ~S"""
  Extracts the options and the algorithm used to generate *hash*.

  Returns `{:error, :invalid}` if *hash* is invalid or not recognized by `available_algorithms/0`.
  """
  @spec get_options(hash :: ExPassword.Algorithm.hash) :: {:ok, ExPassword.Algorithm.options} | {:error, :invalid}
  def get_options(hash)
    when is_binary(hash)
  do
    with(
      module when not is_nil(module) <- find_algorithm(hash),
      {:ok, options} <- module.get_options(hash)
    ) do
        {:ok, Map.put(options, :provider, module)}
    else
      _ ->
        {:error, :invalid}
    end
  end
end
