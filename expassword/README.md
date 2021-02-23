# ExPassword

This is a "port" of PHP password functions.

If you never used them, when you write an authentication system, you have to stick to the initial algorithm you chose.

This is not really acceptable, you should be able to change the hashing algorithm or its options at any time, without asking your users to reset their password. The goal here, when a change like that happens, is to ensure compatibility with previous algorithms and transparently update their hash when they successfuly log in.

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed by adding `expassword` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:expassword, ">= 0.0.0"},
    # with at least one the following
    {:expassword_argon2, ">= 0.0.0"},
    {:expassword_bcrypt, ">= 0.0.0"},
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

  def create(conn, %{"session" => %{"name" => login, "password" => password}}) do
    user = MyApp.Context.Users.get_user_by(name: login)
    case ExPassword.x(user, password) do
      {:ok, change} ->
        if change do
          user
          |> Ecto.Changeset.change(change)
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
