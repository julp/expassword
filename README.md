# ExPassword

This is a "port" of PHP password\_\* functions. To me, one of the best features of PHP.

If you don't know them the benefits are multiple:

* **simple** to use:
  + API remains the same even if you switch to another hashing algorithm
  + only 6 functions (`available_algorithms/0`, `get_options/1`, `hash/3`, `needs_rehash?/3`, `verify?/2`, `verify_and_rehash_if_needed/6` - but you'll probably only use at most 3 of them)
* **extensible** thanks to Elixir. It can't do much on its own since it is a top abstraction layer but by adding a plugin (meaning an hex package as dependency in `deps/0` to your *mix.exs* file) you could support any hashing/method algorithm you'd want. For now, only bcrypt and argon2 are currently supported but with 2 different implementations, one relaying on the PHP command if you really can't build a NIF
* **flexible**
  + in contrast to the traditional way where you are not limited to one hashing method at the time neither stuck with it. You can, **if you want to**, "decipher" (verify) a password hashed in, for example, argon2 (your current choice) and bcrypt (your previous hashing algorithm) and/or whatever you want - but you still can (should) only "cipher" (hash) with a given algorithm. This is possible as long as you keep, both, the hex packages for argon2 and bcrypt as dependencies. The day you want to drop support for good of bcrypt (and, de facto, invalidate the passwords still hashed with bcrypt), you just need to remove this dependency related to bcrypt
  + "passwords" (hashes to be precise) can be transparently migrated. Let's say you started an application with bcrypt (`:expassword_bcrypt`) but then:
    * you estimate your *cost* has become too weak and you want to bump it, no problem: after that change, any active user will automaticaly updates \* its own hash
    * your over-estimated the cost, it is too high? same
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
    {:expassword, "~> 0.2"},
    # with at least one the following
    {:expassword_argon2, "~> 0.2"},
    {:expassword_bcrypt, "~> 0.2"},
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

NOTES:

* this is more a pseudo code than a real code
* in the code above *algorithm* and *options* are runtime values but if you want to make them compile-time instead, for security and/or performance reasons, you can, of course, do so (by hardcoding them somehow or using `Application.compile_env!/2` instead of `Application.fetch_env!/2`)

## Dummy example: migrating an old application from SHA1

As an example (a very bad one), let's pretend we have a very old application where password hashed in SHA1 without salt and want to migrate to argon2. What should we do?

The first step is to write some kind of ExPassword SHA1 plugin. This is very straightforward. After a `mix new expassword_sha1` and creating/modifying the following files:

```elixir
# lib/expassword_sha1/application.ex

defmodule ExPassword.SHA1.Application do
  use Application

  @impl Application
  def start(_type, _args) do
    ExPassword.Registry.register_algorithm(ExPassword.SHA1)

    Supervisor.start_link([], strategy: :one_for_one)
  end
end
```

```elixir
# lib/expassword_sha1.ex

defmodule ExPassword.SHA1 do
  use ExPassword.Algorithm

  @impl ExPassword.Algorithm
  def hash(password, _options) do
    raise ~S"""
    :expassword_sha1 is only intended to migrate old hashes from an old application.

    SHA1 is obsolete, it MUST no longer be used. Besides, passwords MUST be salted.
    """
  end

  @impl ExPassword.Algorithm
  def needs_rehash?(_hash, _options) do
    false
  end

  defp hash_for_verify(password) do
    :sha
    |> :crypto.hash(password)
    |> Base.encode16(case: :lower)
  end

  System.otp_release()
  |> String.to_integer()
  |> Kernel.>=(25)
  |> if do
    defp hash_equals(left, right), do: :crypto.hash_equals(left, right)
  else
    defp hash_equals(left, right), do: Plug.Crypto.secure_compare(left, right)
  end

  @impl ExPassword.Algorithm
  def verify?(password, stored_hash) do
    password
    |> hash_for_verify()
    |> :hash_equals(stored_hash)
  end

  @impl ExPassword.Algorithm
  def get_options(_hash) do
    {:ok, %{algo: "SHA1"}}
  end

  @impl ExPassword.Algorithm
  def valid?(<<"{SHA1}", _rest::binary-size(40)>>), do: true
  def valid?(_hash), do: false
end
```

In the pre-generated mix.exs file, add the following (green) lines:

```diff
     def application do
       [
+        mod: {ExPassword.SHA1.Application, []},
       ]
     end

     # ...

+    System.otp_release()
+    |> String.to_integer()
+    |> Kernel.>=(25)
+    |> if do
+      defp otp_deps, do: []
+    else
+      defp otp_deps, do: [{:plug_crypto, "~> 1.2"}]
+    end

     def deps do
+      otp_deps() ++
       [
         # ...
```

Then, add it to your application in its mix.exs (to the list of `deps/0` function):

```
  {:expassword_sha1, path: "/path/to/the/expassword_sha1/application/created/earlier/by/mix"},
```

(as a local path, you could also use git or host it on hex.pm)

Finaly, migrate your hashes for additional safety:

```postgresql
-- rename the encrypted_password column to old_sha1_encrypted_password
ALTER TABLE users RENAME COLUMN encrypted_password TO old_sha1_encrypted_password;
-- create a new encrypted_password column to store the new hash
ALTER TABLE users ADD COLUMN encrypted_password <TODO: type>;
-- copy the data from the column old_sha1_encrypted_password to encrypted_password
UPDATE users SET encrypted_password = old_sha1_encrypted_password;
-- add the 'SHA1' prefix to clearly identify the old hashes
UPDATE users SET encrypted_password = CONCAT('{SHA1}', TOLOWER(encrypted_password)) WHERE encrypted_password IS NOT NULL;
```

Or, with an Ecto migration:

```elixir
# priv/repo/migrations/<current timestamp or custom version number>_sha1_migration.exs

defmodule YourApp.Repo.Migrations.SHA1Migration do
  use Ecto.Migration

  @users_table "users"
  @encrypted_password_column :encrypted_password
  @backup_column_name :old_sha1_encrypted_password

  def up do
    alias YourApp.Repo
    import Ecto.Query

    # rename the encrypted_password column to old_sha1_encrypted_password
    rename table(@users_table), @encrypted_password_column, to: @backup_column_name
    # create a new encrypted_password column to store the new hash
    alter table(@users_table) do
      add @encrypted_password_column, :binary, null: true # turn it to false if you don't want (hashed) password to be NULL (could be used to indicate that an account is disabled/soft deleted)
    end
    flush()
    # copy the data from the column old_sha1_encrypted_password to encrypted_password
    from(
      u in @users_table,
      update: [
        set: [{^@encrypted_password_column, field(u, ^@backup_column_name)}],
      ]
    )
    |> Repo.update_all([])
    # add the 'SHA1' prefix to clearly identify the old hashes
    from(
      u in @users_table,
      where: not is_nil(field(u, ^@encrypted_password_column)),
      update: [
        # MySQL
        #set: [{^@encrypted_password_column, fragment("CONCAT('{SHA1}', LOWER(?))", field(u, ^@encrypted_password_column))}],
        # PostgreSQL
        set: [{^@encrypted_password_column, fragment("DECODE(CONCAT('{SHA1}', LOWER(ENCODE(?, 'escape'))), 'escape')", field(u, ^@encrypted_password_column))}],
      ]
    )
    |> Repo.update_all([])
  end

  def down do
    alter table(@users_table) do
      remove @encrypted_password_column
    end
    rename table(@users_table), @backup_column_name, to: @encrypted_password_column
  end
end
```

Let time do its work and when you are done with those old SHA1 hashes:

1. remove `:expassword_sha1` from the dependencies of your application
2. drop the old_sha1_encrypted_password column (`ALTER TABLE users DROP COLUMN old_sha1_encrypted_password;`)
