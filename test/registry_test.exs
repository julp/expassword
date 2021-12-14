defmodule ExPassword.RegistryTest do
  use ExUnit.Case
  doctest ExPassword.Registry

  #setup do
    #ExPassword.Registry.clear()
  #end

  defp reset_available_algorithms(fun)
    when is_function(fun, 0)
  do
    algos = ExPassword.Registry.available_algorithms()
    fun.()
    ExPassword.Registry.clear()
    for algo <- algos do
      ExPassword.Registry.register_algorithm(algo)
    end
  end

  test "ExPassword.Registry.register_algorithm/1" do
    for algo <- ExPassword.Test.Set.algorithms() do
      assert algo in ExPassword.Registry.available_algorithms()
    end
    refute __MODULE__ in ExPassword.Registry.available_algorithms()
    reset_available_algorithms(
      fn ->
        ExPassword.Registry.register_algorithm(__MODULE__)
        assert __MODULE__ in ExPassword.Registry.available_algorithms()
      end
    )
    refute __MODULE__ in ExPassword.Registry.available_algorithms()
  end

  test "ExPassword.Registry.supported_algorithm?/1" do
    for algo <- ExPassword.Test.Set.algorithms() do
      assert ExPassword.Registry.supported_algorithm?(algo)
    end
    refute ExPassword.Registry.supported_algorithm?(__MODULE__)
    reset_available_algorithms(
      fn ->
        ExPassword.Registry.register_algorithm(__MODULE__)
        assert ExPassword.Registry.supported_algorithm?(__MODULE__)
      end
    )
    refute ExPassword.Registry.supported_algorithm?(__MODULE__)
  end
end
