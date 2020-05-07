defmodule ExPassword do
  @moduledoc """
  Documentation for ExPassword.
  """

  @type algorithm :: module | :default

  @known_algorithms [
    # implies :expassword_bcrypt listed as dependency in your mix.exs
    Bcrypt,
    # <testing only>
    ExPassword.MD5,
    ExPassword.SHA1,
    ExPassword.SSHA,
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
  TODO
  """
  @spec hash(algorithm :: algorithm, password :: ExPassword.Algorithm.password, options :: ExPassword.Algorithm.options) :: boolean
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
  @spec verify?(password :: ExPassword.Algorithm.password, hash :: ExPassword.Algorithm.hash) :: boolean
  def verify?(password, hash) do
    find_algorithm(hash).verify?(password, hash)
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
  @spec get_options(hash :: ExPassword.Algorithm.hash) :: ExPassword.Algorithm.options
  def get_options(hash) do
    module = find_algorithm(hash)
    module.get_options(hash)
    |> Map.put(:provider, module)
  end
end
