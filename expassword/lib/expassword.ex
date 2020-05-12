defmodule ExPassword do
  @moduledoc """
  Documentation for ExPassword.
  """

  @type algorithm :: module | :default

  @known_algorithms [
    # implies :expassword_bcrypt listed as dependency in your mix.exs
    Bcrypt,
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

  @doc false
  def available_algorithms do
    @available_algorithms
  end

  @doc ~S"""
  TODO
  """
  @spec x(user :: struct | nil, password :: ExPassword.Algorithm.password, field :: atom) :: {:ok, ExPassword.Algorithm.hash | nil} | {:error, :atom}
  def x(user, password, field \\ :encrypted_password)

  def x(nil, password, _field) do
    ExPassword.hash(:default, password)
    {:error, :user_is_nil}
  end

  def x(user, password, field) do
    hash = Map.fetch!(user, field)
    case ExPassword.verify?(password, hash) do
      true -> # TODO: {:ok, ?}
        change = if ExPassword.needs_rehash?(:default, hash) do # TODO
          [{field, ExPassword.hash(:default, password)}]
        end
        {:ok, change}
      false -> # TODO: {:error, ?}
        {:error, :password_missmatch}
    end
  end

  @doc ~S"""
  TODO
  """
  @spec hash(algorithm :: algorithm, password :: ExPassword.Algorithm.password, options :: ExPassword.Algorithm.options) :: ExPassword.Algorithm.hash | no_return
  def hash(algorithm, password, options \\ %{})

  def hash(:default, password, options) do
    :expassword
    |> Application.fetch_env!(:default)
    |> hash(password, options)
  end

  def hash(algorithm, password, options) do
    algorithm.hash(password, options)
  end

  @doc ~S"""
  TODO
  """
  @spec verify?(password :: ExPassword.Algorithm.password, hash :: ExPassword.Algorithm.hash) :: boolean | no_return
  def verify?(password, hash) do
    case find_algorithm(hash) do
      nil ->
        raise ExPassword.UnidentifiedAlgorithmError, hash: hash
      algorithm ->
        algorithm.verify?(password, hash)
    end
  end

  @doc ~S"""
  TODO
  """
  @spec needs_rehash?(algorithm :: algorithm, hash :: ExPassword.Algorithm.hash, options :: ExPassword.Algorithm.options) :: boolean
  def needs_rehash?(algorithm, hash, options \\ %{})
    when algorithm in @available_algorithms
  do
    case find_algorithm(hash) do
      ^algorithm ->
        algorithm.needs_rehash?(hash, options)
      _ ->
        true
    end
  end

  @doc ~S"""
  TODO
  """
  @spec get_options(hash :: ExPassword.Algorithm.hash) :: {:ok, ExPassword.Algorithm.options} | {:error, :invalid}
  def get_options(hash) do
    module = find_algorithm(hash)
    case module.get_options(hash) do
      {:ok, options} ->
        {:ok, Map.put(options, :provider, module)}
      any ->
        any
    end
  end
end
