defmodule Mix.Tasks.ExPassword.Check do
  use Mix.Task

  #defp print_options(options) when options == %{}, do: nil
  defp print_options(options) do
    if Enum.any?(options) do
      IO.puts("")
      IO.puts("Options that were used for the hashing:")
      Enum.each(
        options,
        fn {k, v} ->
          IO.puts("- #{k}: #{inspect(v)}")
        end
      )
    end
  end

  @shortdoc "Checks if a password matches a hash"
  def run(args) do
    {_opts, parsed, _unknown} = OptionParser.parse(args, switches: [])
    [password, hash] = parsed
    #try do
      result = ExPassword.verify?(password, hash)
    #rescue
      #_ ->
        #System.halt(:abort)
    #end
    IO.puts "ExPassword.verify?(#{inspect(password)}, #{inspect(hash)}) = #{inspect(result)}"
    {:ok, options} = ExPassword.get_options(hash)
    print_options(options)
  end
end
