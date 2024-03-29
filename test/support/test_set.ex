defmodule ExPassword.Test.Set do

  @type salt :: binary | nil
  @type test :: {ExPassword.Algorithm.password, ExPassword.Algorithm.hash, salt}

  @callback test_set() :: [test]

  defmacro __using__(_options) do
    quote do
      import unquote(__MODULE__)
      @behaviour unquote(__MODULE__)
    end
  end

  def algorithms do
    [
      ExPassword.Test.MD5,
      ExPassword.Test.SHA1,
      ExPassword.Test.SSHA,
    ]
  end
end
