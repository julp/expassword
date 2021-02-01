defmodule ExPassword.Argon2 do
  use ExPassword.Algorithm

  @invalid {:error, :invalid}
  @default_options %{type: :argon2id, threads: 2, memory_cost: 131072, time_cost: 4}
  #@default_options Enum.into(Application.get_all_env(:expassword_argon2), %{})

  if :prod == Mix.env() do
    raise ~S"""
    :expassword_external_argon2 is only intended to be used on a development and/or
    test environment as a convenient way to avoid compiling a C NIF.

    Make sure that in your mix.exs file, in deps/1 function to have like the following:

      {:expassword_argon2, ">= 0.0.0", only: :prod},
      {:expassword_external_argon2, ">= 0.0.0", only: ~W[dev test]a},
    """
  end

  @impl ExPassword.Algorithm
  def hash(password, options) do
    options = Map.merge(@default_options, options)
    algo = case Map.get(options, :type, :argon2i) do
      :argon2i ->
        "PASSWORD_ARGON2I"
      :argon2id ->
        "PASSWORD_ARGON2ID"
    end
    memory_cost = Map.get(options, :memory_cost, 131072)
    time_cost = Map.get(options, :time_cost, 4)
    threads = Map.get(options, :threads, 2)
    code = ~S"""
    echo password_hash(
      $argv[1],
      constant($argv[2]),
      [
        'memory_cost' => $argv[3],
        'time_cost' => $argv[4],
        'threads' => $argv[5],
      ]
    );
    """
    {result, 0} = System.cmd("php", ["-r", code, "--", password, algo, to_string(memory_cost), to_string(time_cost), to_string(threads)])
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

  defp parse_p(acc, ",p=" <> rest) do
    case Integer.parse(rest) do
      {value, "$" <> _rest} ->
        {:ok, Map.put(acc, :threads, value)}
      _ ->
        @invalid
    end
  end

  defp parse_p(_acc, _subhash), do: @invalid

  defp parse_t(acc, ",t=" <> rest) do
    case Integer.parse(rest) do
      {value, rest} ->
        acc
        |> Map.put(:time_cost, value)
        |> parse_p(rest)
      :error ->
        @invalid
    end
  end

  defp parse_t(_acc, _subhash), do: @invalid

  defp parse_m(acc, "$m=" <> rest) do
    case Integer.parse(rest) do
      {value, rest} ->
        acc
        |> Map.put(:memory_cost, value)
        |> parse_t(rest)
      :error ->
        @invalid
    end
  end

  defp parse_m(_acc, _subhash), do: @invalid

  defp parse_v(acc, "$v=" <> rest) do
    case Integer.parse(rest) do
      {value, rest} ->
        acc
        |> Map.put(:version, value)
        |> parse_m(rest)
      :error ->
        @invalid
    end
  end

  defp parse_v(acc, subhash = "$m=" <> _rest) do
    acc
    |> Map.put(:version, 16)
    |> parse_m(subhash)
  end

  defp parse_v(_acc, _subhash), do: @invalid

  @impl ExPassword.Algorithm
  def get_options("$argon2id" <> rest) do
    parse_v(%{type: :argon2id}, rest)
  end

  def get_options("$argon2i" <> rest) do
    parse_v(%{type: :argon2i}, rest)
  end

  def get_options(_hash) do
    @invalid
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
