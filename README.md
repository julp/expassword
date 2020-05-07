# ExPassword

This is a port of PHP password functions.

If you never used them, when you write an authentication system, you have to stick to the initial algorithm you chose.

This is not really acceptable, you should have the ability to change the hashing algorithm or its options at any time, without asking your users to reset their password. The goal here, when a change like that happens, is to ensure compatibility with previous algorithms and transparently update their hash when they successfuly log in.

## Installation

~~If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `expassword` to your list of dependencies in `mix.exs`:~~

This is not ready for production neither published on Hex, so to use it in one of your project, you have to modify your mix.exs file like so:

```elixir
def deps do
  [
    {:expassword, git: "https://github.com/julp/expassword.git", branch: "master"},
    {:bcrypt_elixir, git: "https://github.com/julp/bcrypt_elixir.git", branch: "expassword"},
  ]
end
```

~~Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/expassword](https://hexdocs.pm/expassword).~~
