defmodule ExPassword.Bcrypt do
  use ExPassword.Algorithm

  @default_options %{cost: 10}
  #@default_options Enum.into(Application.get_all_env(:expassword_argon2), %{})

  if :prod == Mix.env() do
    raise ~S"""
    :expassword_external_bcrypt is only intended to be used on a development and/or
    test environment as a convenient way to avoid compiling a C NIF.

    Make sure that in your mix.exs file, in deps/1 function to have like the following:

      {:expassword_bcrypt, ">= 0.0.0", only: :prod},
      {:expassword_external_bcrypt, ">= 0.0.0", only: ~W[dev test]a},
    """
  end

  @impl ExPassword.Algorithm
  def hash(password, options) do
    options = Map.merge(@default_options, options)
    cost = Map.get(options, :cost, 2)
    code = ~S"""
    echo password_hash(
      $argv[1],
      PASSWORD_BCRYPT,
      [
        'cost' => $argv[2],
      ]
    );
    """
    {result, 0} = System.cmd("php", ["-r", code, "--", password, to_string(cost)])
    String.trim_trailing(result, "\r\n")
  end

  @impl ExPassword.Algorithm
  def verify?(hash, password) do
    code = ~S"""
    echo password_verify(
      $argv[1],
      $argv[2]
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
  def needs_rehash?(hash, new_options) do
    case get_options(hash) do
      {:ok, old_options} ->
        #Map.delete(old_options, :provider) != new_options
        old_options != new_options
      _ ->
        raise ArgumentError
    end
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
