defmodule ExPassword.Argon2 do
  use ExPassword.Algorithm

  @invalid {:error, :invalid}

  if :prod == Mix.env() do
    raise ~S"""
    :expassword_external_argon2 is only intended to be used on a development and/or
    test environment as a convenient way to avoid compiling a C NIF.

    Make sure that in your mix.exs file, in deps/1 function to have like the following:

      {:expassword_argon2, ">= 0.0.0", only: :prod},
      {:expassword_external_argon2, ">= 0.0.0", only: ~W[dev test]a},
    """
  end

  defguardp is_valid_type(type) when type in ~W[argon2i argon2id]a
  defguardp is_valid_threads(threads) when is_integer(threads) and threads >= 1
  defguardp is_valid_time_cost(time_cost) when is_integer(time_cost) and time_cost >= 1
  defguardp is_valid_memory_cost(memory_cost) when is_integer(memory_cost) and memory_cost >= 16

  defp raise_invalid_options(options) do
    raise ArgumentError, """
    Expected options parameter to have the following keys:

    - type: the atom :argon2i or :argon2id
    - threads: an integer >= 1
    - time_cost: an integer >= 1
    - memory_cost: an integer >= 16
    - version (optional): the integer 16 or 19

    Instead, got: #{inspect(options)}
    """
  end

  @impl ExPassword.Algorithm
  def hash(password, %{type: type, threads: threads, time_cost: time_cost, memory_cost: memory_cost})
    when is_valid_type(type) and is_valid_threads(threads) and is_valid_time_cost(time_cost) and is_valid_memory_cost(memory_cost)
  do
    algo = case type do
      :argon2i ->
        "PASSWORD_ARGON2I"
      :argon2id ->
        "PASSWORD_ARGON2ID"
    end
    code = ~S"""
    list(, $password, $algorithm, $memory_cost, $time_cost, $threads) = $argv;
    echo password_hash(
      $password,
      constant($algorithm),
      [
        'memory_cost' => $memory_cost,
        'time_cost' => $time_cost,
        'threads' => $threads,
      ]
    );
    """
    {result, 0} = System.cmd("php", ["-r", code, "--", password, algo, to_string(memory_cost), to_string(time_cost), to_string(threads)])
    String.trim_trailing(result, "\r\n")
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
  def needs_rehash?(hash, new_options = %{type: type, threads: threads, time_cost: time_cost, memory_cost: memory_cost})
    when is_valid_type(type) and is_valid_threads(threads) and is_valid_time_cost(time_cost) and is_valid_memory_cost(memory_cost)
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
