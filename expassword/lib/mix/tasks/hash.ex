if false do
  defmodule Mix.Tasks.ExPassword.Hash do
    use Mix.Task

    defp parse_module(name) do
      Module.concat([name])
    end

    defp guess_options(module) do
      {:ok, options} =
        module
        |> ExPassword.hash("")
        |> ExPassword.get_options()
      options
    end

    defp handle_options(default, user) do
      Enum.reduce(
        default,
        %{},
        fn {k, v}, acc ->
          if user_value = Keyword.get(user, k) do
            new_value = cond do
              is_binary(v) ->
                user_value
              is_integer(v) ->
                String.to_integer(user_value)
              is_atom(v) ->
                String.to_existing_atom(user_value)
              true ->
                nil
            end
            if new_value do
              Map.put(acc, k, new_value)
            else
              Map.put(acc, k, v)
            end
          else
            Map.put(acc, k, v)
          end
        end
      )
    end

    #defp print_options(options) when options == %{}, do: nil
    defp print_options(options) do
      if Enum.any?(options) do
        IO.puts("")
        IO.puts("Options that were used for hashing:")
        Enum.each(
          options,
          fn {k, v} ->
            IO.puts("- #{k}: #{inspect(v)}")
          end
        )
      end
    end

    @shortdoc "Hashes a password"
    def run(args) do
      {opts, parsed, _unknown} = OptionParser.parse(args, switches: [])
      [algorithm, password] = parsed
      algorithm = parse_module(algorithm)
      unless algorithm in ExPassword.available_algorithms() do
        IO.puts """
        #{inspect(algorithm)} is not one of the algorithms supported by ExPassword.

        You may need an extra dependency in your mix.exs to support it.
        """
        System.halt(:abort)
      end
      user_options =
        algorithm
        |> guess_options()
        |> handle_options(opts)
      hash = ExPassword.hash(algorithm, password, user_options)
      IO.puts "ExPassword.hash(#{inspect(algorithm)}, #{inspect(password)}) = #{inspect(hash)}"
      print_options(user_options)
    end
  end
end
