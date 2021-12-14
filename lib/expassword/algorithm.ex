defmodule ExPassword.Algorithm do
  @moduledoc ~S"""
  Defines an algorithm to be used by ExPassword as a behaviour to be implemented
  """

  @type hash :: binary
  @type password :: binary
  @type options :: %{optional(atom) => any}

  @doc ~S"""
  Callback to compute the hash of *password* with the given *options* (algorithm specific)

  May raise in case of internal failure or if an option is invalid
  """
  @callback hash(password :: password, options :: options) :: hash | no_return

  @doc ~S"""
  This callback should return `true` if the options initially used to produce *hash* are
  somehow different to *options*. Its goal is to indicate if the password should be rehashed
  because these options have since changed, in particular if they are now too weak.

  Raises if *options* is invalid
  """
  @callback needs_rehash?(hash :: hash, options :: options) :: boolean | no_return

  @doc ~S"""
  Callback to check if the provided *password* matches the reference hash *stored_hash*

  May raise in case of internal failure or if *stored_hash* is invalid
  """
  @callback verify?(password :: password, stored_hash :: hash) :: boolean | no_return

  @doc ~S"""
  Callback to extract the options initially used to produce *hash* from the hash itself

  Returns `{:error, :invalid}` if the hash is invalid to the current algorithm else
  `{:ok, options}` where options is a `Map` filled with the values of the options
  specific to the current hashing method.
  """
  @callback get_options(hash :: hash) :: {:ok, options} | {:error, :invalid}

  @doc ~S"""
  Callback to determine if a given hash is valid to the current algorithm.

  It might be used for validation but its primary purpose is to identify (find) the
  algorithm from which were generated the given hash.
  """
  @callback valid?(hash :: hash) :: boolean

  defmacro __using__(_opts) do
    quote do
      #import unquote(__MODULE__)
      @behaviour unquote(__MODULE__)
    end
  end
end
