defmodule ExPassword.Algorithm do
  @moduledoc ~S"""
  Defines an algorithm to be used by ExPassword
  """

  @type hash :: binary
  @type password :: binary
  @type options :: %{optional(atom) => any}

  @doc ~S"""
  TODO
  """
  @callback hash(password :: password, options :: options) :: hash | no_return

  @doc ~S"""
  TODO
  """
  @callback needs_rehash?(hash :: hash, options :: options) :: boolean

  @doc ~S"""
  TODO
  """
  @callback verify?(password :: password, stored_hash :: hash) :: boolean | no_return

  @doc ~S"""
  TODO
  """
  @callback get_options(hash :: hash) :: options

  @doc ~S"""
  TODO
  """
  @callback valid?(hash :: hash) :: boolean

  defmacro __using__(_opts) do
    quote do
      #import unquote(__MODULE__)
      @behaviour unquote(__MODULE__)
    end
  end
end
