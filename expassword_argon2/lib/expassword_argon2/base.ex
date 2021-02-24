defmodule ExPassword.Argon2.Base do
  @moduledoc false

  @compile {:autoload, false}
  @on_load :load_nifs

  def load_nifs do
    :expassword_argon2
    |> :code.priv_dir()
    |> :filename.join('argon2_nif')
    |> :erlang.load_nif(0)
    |> case do
      :ok ->
        :ok
      _ ->
        raise ~S"""
        An error occurred when loading Argon2.
        Make sure you have a C compiler and Erlang 20 installed.
        """
    end
  end

  def hash_nif(password, salt, options)
  def hash_nif(_password, _salt, _options), do: :erlang.nif_error(:not_loaded)

  def verify_nif(password, hash)
  def verify_nif(_password, _hash), do: :erlang.nif_error(:not_loaded)

  def get_options_nif(hash)
  def get_options_nif(_hash), do: :erlang.nif_error(:not_loaded)

  def needs_rehash_nif(hash, options)
  def needs_rehash_nif(_hash, _options), do: :erlang.nif_error(:not_loaded)

  def valid_nif(hash)
  def valid_nif(_hash), do: :erlang.nif_error(:not_loaded)
end
