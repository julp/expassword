# ExPassword

This is a "port" of PHP password\_\* functions.

If you never used them, when you write an authentication system, you have to stick to the initial algorithm you chose.

This is not really acceptable, you should be able to change the hashing algorithm or its options at any time, without asking your users to reset their password. The goal here, when a change like that happens, is to ensure compatibility with previous algorithms and transparently update their hash when they successfuly log in.

Let's say you started an application with bcrypt (`:expassword_bcrypt`). But then:

* you estimate your *cost* has become too weak and you want to bump it, no problem: after that change, any active user will automaticaly updates \* its own hash
* you want to switch from bcrypt to argon2 (`:expassword_argon2`), same, no problem:
  + old users with a bcrypt hash can still login as long as you keep `:expassword_bcrypt` in your `deps/0` (mix.exs file)
  + any active user with a bcrypt hash will automaticaly be updated \* to a new argon2 hash
* you finaly want to end your support for bcrypt (old inactive users - they'll have to use your *reset password* feature to recover their account) after a period of transition, fine, just remove `:expassword_bcrypt` from `deps/0`

\* if you want and do it

But, wait, on my *dev* and/or *test* environments I can't compile NIFs. No problem: install PHP (have to be present in your PATH) and replace `:expassword_bcrypt` by `:expassword_external_bcrypt` and `:expassword_argon2` by `:expassword_external_argon2` (more details in their respective README.md)

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed by adding `expassword` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:expassword, "~> 0.1"},
    # with at least one the following
    {:expassword_argon2, "~> 0.1"},
    {:expassword_bcrypt, "~> 0.1"},
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc) and published on [HexDocs](https://hexdocs.pm). Once published, the docs can be found at [https://hexdocs.pm/expassword](https://hexdocs.pm/expassword).

## Usage

```elixir
defmodule MyAppWeb.SessionController do
  # ...

  @application :my_app
  def create(conn, %{"session" => %{"name" => login, "password" => password}}) do
    algorithm = Application.fetch_env!(@application, :password_algorithm)
    options = Application.fetch_env!(@application, :password_options)
    user = MyApp.Context.Users.get_user_by(name: login)
    if user do
      if ExPassword.verify?(password, user.encrypted_password) do
        if ExPassword.needs_rehash?(user.encrypted_password, options) do
          user
          |> Ecto.Changeset.change(encrypted_password: ExPassword.hash(algorithm, password, options))
          |> MyApp.Repo.update!()
        end

        conn
        |> put_flash(:info, "successfully authenticated")
        |> put_session(:user_id, user.id)
        |> redirect(to: "/")
      else
        conn
        |> put_flash(:error, "authentication failed")
        |> render("new.html")
      end
    else
      ExPassword.hash(algorithm, password, options) # for timing attacks

      conn
      |> put_flash(:error, "authentication failed")
      |> render("new.html")
    end
  end

  # same using the convenient ExPassword.verify_and_rehash_if_needed/6
  def create(conn, %{"session" => %{"name" => login, "password" => password}}) do
    algorithm = Application.fetch_env!(@application, :password_algorithm)
    options = Application.fetch_env!(@application, :password_options)
    user = MyApp.Context.Users.get_user_by(name: login)
    case ExPassword.verify_and_rehash_if_needed(user, password, algorithm, options) do
      {:ok, changes} ->
        if changes != [] do
          user
          |> Ecto.Changeset.change(changes)
          |> MyApp.Repo.update!()
        end
        conn
        |> put_flash(:info, "successfully authenticated")
        |> put_session(:user_id, user.id)
        |> redirect(to: "/")
      {:error, _reason} ->
        conn
        |> put_flash(:error, "authentication failed")
        |> render("new.html")
    end
  end
end
```

(this is more a pseudo code than real code)
