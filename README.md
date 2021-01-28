This is a repository for the following hex packages:

* [expassword_algorithm](https://hexdocs.pm/expassword_algorithm): for the module which serves as behaviour to support new hashing methods
* [expassword](https://hexdocs.pm/expassword): the base of ExPassword but it does not include any hashing algorithm, you have to list them as dependencies in your mix.exs
* [expassword_argon2](https://hexdocs.pm/expassword_argon2) (NIF): to add support for Argon2 to ExPassword
* [expassword_bcrypt](https://hexdocs.pm/expassword_bcrypt) (NIF): to add support for Bcrypt to ExPassword

So to use expassword you need `:expassword` in your deps/0 function of your mix.exs file and at least one of `:expassword_argon2` or `:expassword_bcrypt`

```elixir
def deps do
  [
    {:expassword, ">= 0.0.0"},
    {:expassword_argon2, ">= 0.0.0"},
    {:expassword_bcrypt, ">= 0.0.0"},
  ]
end
```
