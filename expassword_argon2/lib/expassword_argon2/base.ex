defmodule ExPassword.Argon2.Base do
  @moduledoc ~S"""
  TODO
  """

  @compile {:autoload, false}
  @on_load :load_nifs

  @doc false
  def load_nifs do
    case :erlang.load_nif('priv/argon2_nif', 0) do
      :ok ->
        :ok
      _ ->
        raise ~S"""
        An error occurred when loading Argon2.
        Make sure you have a C compiler and Erlang 20 installed.
        """
    end
  end

  @doc ~S"""
  TODO
  """
  def hash_nif(password, salt, options)
  def hash_nif(_password, _salt, _options), do: :erlang.nif_error(:not_loaded)

  @doc ~S"""
  TODO
  """
  def verify_nif(hash, password)
  def verify_nif(_hash, _password), do: :erlang.nif_error(:not_loaded)

  @doc ~S"""
  TODO
  """
  def get_options_nif(hash)
  def get_options_nif(_hash), do: :erlang.nif_error(:not_loaded)

  @doc ~S"""
  TODO
  """
  def needs_rehash_nif(hash, options)
  def needs_rehash_nif(_hash, _options), do: :erlang.nif_error(:not_loaded)

  @doc ~S"""
  TODO
  """
  def valid_nif(hash)
  def valid_nif(_hash), do: :erlang.nif_error(:not_loaded)
end
