defmodule ExPassword.Bcrypt.Base do
  @moduledoc false

  @compile {:autoload, false}
  @on_load :load_nifs

  def load_nifs do
    :expassword_bcrypt
    |> :code.priv_dir()
    |> :filename.join('bcrypt_nif')
    |> :erlang.load_nif(0)
    |> case do
      :ok ->
        :ok
      _ ->
        raise ~S"""
        An error occurred when loading Bcrypt.
        Make sure you have a C compiler and Erlang 20 installed.
        """
    end
  end

  def generate_salt_nif(salt, options)
  def generate_salt_nif(_salt, _options), do: :erlang.nif_error(:not_loaded)

  def hash_nif(password, salt)
  def hash_nif(_password, _salt), do: :erlang.nif_error(:not_loaded)

  def verify_nif(password, hash)
  def verify_nif(_password, _hash), do: :erlang.nif_error(:not_loaded)

  def get_options_nif(hash)
  def get_options_nif(_hash), do: :erlang.nif_error(:not_loaded)

  def needs_rehash_nif(hash, options)
  def needs_rehash_nif(_hash, _options), do: :erlang.nif_error(:not_loaded)

  def valid_nif(hash)
  def valid_nif(_hash), do: :erlang.nif_error(:not_loaded)

  if false do
    def encode_base64_nif(data)
    def encode_base64_nif(_data), do: :erlang.nif_error(:not_loaded)

    def decode_base64_nif(data)
    def decode_base64_nif(_data), do: :erlang.nif_error(:not_loaded)
  end
end
