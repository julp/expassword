defmodule ExPassword.UnidentifiedAlgorithmError do
  @moduledoc """
  Exception raised when no suitable algorithm were found from a hash
  """
  defexception ~W[message]a

  def exception(opts) do
    hash = Keyword.fetch!(opts, :hash)
    %__MODULE__{
      message: """
      No suitable algorithm were found from the hash: #{inspect(hash)}

      Make sure ExPassword was built with the according algorithm by
      adding it to your mix.exs file.
      """
    }
  end
end
