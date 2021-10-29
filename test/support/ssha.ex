defmodule ExPassword.Test.SSHA do
  @moduledoc ~S"""
  This module is only used for testing purpose, do **NOT** use it in real world!
  """

  use ExPassword.Test.Set

  @impl ExPassword.Test.Set
  def test_set do
    [
      {"testing123", "{SSHA}0c0blFTXXNuAMHECS4uxrj3ZieMoWImr", <<40, 88, 137, 171>>},
    ]
  end

  use ExPassword.Algorithm

  @prefix "{SSHA}"
  @default_salt_len 16
  @salt_length_option :salt_length
  defp fetch_salt_len(options) do
    Map.get(options, @salt_length_option, @default_salt_len)
  end

  @impl ExPassword.Algorithm
  def hash(password, options) do
    salt = if salt = Map.get(options, :salt) do
      salt
    else
      options
      |> fetch_salt_len()
      |> :crypto.strong_rand_bytes()
    end

    @prefix <> (
      :crypto.hash(:sha, password <> salt)
      |> Kernel.<>(salt)
      |> Base.encode64(case: :lower)
    )
  end

  @impl ExPassword.Algorithm
  def needs_rehash?(<<@prefix, hash::binary>>, options) do
    <<_digest::bytes-size(20), salt::binary>> = Base.decode64!(hash)
    fetch_salt_len(options) > byte_size(salt)
  end

  @impl ExPassword.Algorithm
  def verify?(password, <<@prefix, hash::binary>>) do
    <<digest::bytes-size(20), salt::binary>> = Base.decode64!(hash)
    :crypto.hash(:sha, password <> salt) == digest
  end

  @impl ExPassword.Algorithm
  def get_options(<<@prefix, hash::binary>>) do
    <<_digest::bytes-size(20), salt::binary>> = Base.decode64!(hash)
    {:ok, %{@salt_length_option => byte_size(salt), algo: "SSHA"}}
  end

  @impl ExPassword.Algorithm
  def valid?(<<@prefix, _rest::binary>>), do: true
  def valid?(_), do: false
end
