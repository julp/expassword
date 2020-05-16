# ExpasswordBcrypt

This module add support for Bcrypt to ExPassword

## Prerequisites

* a C99 compiler
* CMake

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `expassword_bcrypt` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:expassword_bcrypt, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/expassword_bcrypt](https://hexdocs.pm/expassword_bcrypt).

## Configuration

Default values are:

```elixir
config :expassword_bcrypt,
  # TODO
  cost: 10
```

Of course, you can override them in your config/*.exs

In fact, you should lower these values in config/test.exs to speed up your tests.
