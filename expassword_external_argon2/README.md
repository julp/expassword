# ExpasswordExternalArgon2

This module add support for Argon2 to ExPassword via an external command (php) for environments where a NIF can't be compiled

## Prerequisites

* [PHP](https://www.php.net/downloads) available via the PATH variable environment

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed by adding `expassword_external_argon2` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:expassword, ">= 0.0.0"},
    {:expassword_external_argon2, "~> 0.1.0", only: ~W[dev test]},
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc) and published on [HexDocs](https://hexdocs.pm). Once published, the docs can be found at [https://hexdocs.pm/expassword_external_argon2](https://hexdocs.pm/expassword_external_argon2).

## Configuration

Default values are:

```elixir
config :expassword_argon2,
  # the algorithm between :argon2id and :argon2i
  type: :argon2_id,
  # number of threads to use
  threads: 2,
  # maximum amount of time
  time_cost: 4,
  # maximum amount of memory that may be used
  memory_cost: 131072
```

Of course, you can override them in your config/*.exs

In fact, you should lower these values in config/test.exs to speed up your tests.
