defmodule ExPassword.Registry do
  @moduledoc ~S"""
  Functions to register new algorithms to ExPassword and to know which hashing methods are available.
  """

  @app :expassword
  @key :algorithms

  @doc ~S"""
  Register a new algorithm (a module which implements `ExPassword.Algorithm`)
  """
  @spec register_algorithm(algorithm :: ExPassword.algorithm) :: :ok
  def register_algorithm(algorithm)
    when is_atom(algorithm)
  do
    algorithms = available_algorithms()
    if algorithm in algorithms do
      :ok
    else
      Application.put_env(@app, @key, [algorithm | algorithms])
    end
  end

  @doc ~S"""
  Returns the list of the modules that currently are enabled and provide support to ExPassword for a hashing method
  """
  @spec available_algorithms() :: [ExPassword.algorithm]
  def available_algorithms do
    Application.get_env(@app, @key, [])
  end

  @doc ~S"""
  Returns `true` if *algorithm* is currently registered as an active hashing method to ExPassword
  """
  @spec supported_algorithm?(algorithm :: ExPassword.algorithm) :: boolean
  def supported_algorithm?(algorithm)
    when is_atom(algorithm)
  do
    algorithm in available_algorithms()
  end

  if Mix.env() == :test do
    @spec clear() :: :ok
    def clear do
      Application.delete_env(@app, @key)
    end
  end
end
