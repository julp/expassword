defmodule ExPassword.Bcrypt do
  use ExPassword.Algorithm

  if :prod == Mix.env() do
    raise ~S"""
    :expassword_external_bcrypt is only intended to be used on a development and/or
    test environment as a convenient way to avoid compiling a C NIF.

    Make sure that in your mix.exs file, in deps/1 function to have like the following:

      {:expassword_bcrypt, ">= 0.0.0", only: :prod},
      {:expassword_external_bcrypt, ">= 0.0.0", only: ~W[dev test]a},
    """
  end

  defguardp is_valid_cost(cost) when is_integer(cost) and cost >= 4 and cost <= 31

  defp raise_invalid_options(options) do
    raise ArgumentError, """
    Expected options parameter to have the following key:
    - cost: an integer in the [4;31] range
    Instead, got: #{inspect(options)}
    """
  end

  @impl ExPassword.Algorithm
  def hash(password, %{cost: cost})
    when is_valid_cost(cost)
  do
    code = ~S"""
    list(, $password, $cost) = $argv;
    echo password_hash(
      $password,
      PASSWORD_BCRYPT,
      [
        'cost' => $cost,
      ]
    );
    """
    {result, 0} = System.cmd("php", ["-r", code, "--", password, to_string(cost)])
    result
    |> String.trim_trailing("\r\n")
    |> String.replace_prefix("$2y$", "$2b$")
  end

  def hash(_password, options) do
    raise_invalid_options(options)
  end

  @impl ExPassword.Algorithm
  def verify?(password, hash) do
    code = ~S"""
    list(, $password, $hash) = $argv;
    echo password_verify(
      $password,
      $hash
    );
    """
    {result, 0} = System.cmd("php", ["-r", code, "--", password, hash])
    "1" == String.trim_trailing(result, "\r\n")
  end

  @impl ExPassword.Algorithm
  def get_options(<<"$2", minor, "$", c1, c2, "$", _rest::bits>>)
    when minor in [?a, ?b, ?y]
    and c1 in ?0..?9
    and c2 in ?0..?9
    and (c1 - ?0) * 10 + c2 - ?0 >= 4
    and (c1 - ?0) * 10 + c2 - ?0 <= 31
  do
    {:ok, %{cost: (c1 - ?0) * 10 + c2 - ?0}}
  end

  def get_options(_hash) do
    {:error, :invalid}
  end

  @impl ExPassword.Algorithm
  def needs_rehash?(hash, new_options = %{cost: cost})
    when is_valid_cost(cost)
  do
    case get_options(hash) do
      {:ok, old_options} ->
        #Map.delete(old_options, :provider) != new_options
        old_options != new_options
      _ ->
        raise ArgumentError
    end
  end

  def needs_rehash?(_hash, options) do
    raise_invalid_options(options)
  end

  @impl ExPassword.Algorithm
  def valid?(hash) do
    #match?({:ok, _options}, get_options(hash)
    case get_options(hash) do
      {:ok, _options} ->
        true
      {:error, :invalid} ->
        false
    end
  end
end
