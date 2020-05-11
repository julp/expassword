# ExPassword

This is a "port" of PHP password functions.

If you never used them, when you write an authentication system, you have to stick to the initial algorithm you chose.

This is not really acceptable, you should be able to change the hashing algorithm or its options at any time, without asking your users to reset their password. The goal here, when a change like that happens, is to ensure compatibility with previous algorithms and transparently update their hash when they successfuly log in.

## Installation

~~If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `expassword` to your list of dependencies in `mix.exs`:~~

This is not ready for production neither published on Hex, so to use it in one of your project, you have to modify your mix.exs file like so:

```elixir
def deps do
  [
    {:expassword, ">= 0.0.0"},
    {:expassword_argon2, ">= 0.0.0"},
    {:expassword_bcrypt, ">= 0.0.0"},
  ]
end
```

~~Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/expassword](https://hexdocs.pm/expassword).~~

## Usage

```elixir
defmodule MyAppWeb.SessionController do
  # ...

  def create(conn, %{"session" => %{"name" => login, "password" => password}}) do
    user = MyApp.Context.Users.get_user_by(name: login)
    if user do
      if ExPassword.verify?(password, user.encrypted_password) do
        if ExPassword.needs_rehash?(user.encrypted_password) do
          user
          |> Ecto.Changeset.change(encrypted_password: ExPassword.hash(:default, password))
          |> MyApp.Repo.update!()
        end

        conn
        |> put_flash(:info, "successfuly authenticated")
        |> put_session(:user_id, user.id)
        |> redirect(to: "/")
      else
        conn
        |> put_flash(:error, "authentication failed")
        |> render("new.html")
      end
    else
      ExPassword.hash(:default, password) # for timing attacks

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
        |> put_flash(:info, "successfuly authenticated")
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

(this is more a pseudo code than a real code)
