defmodule ExPassword.MixProject do
  use Mix.Project

  defp elixirc_paths(:test), do: ~W[lib test/support]
  defp elixirc_paths(_), do: ~W[lib]

  def project do
    [
      app: :expassword,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      if :inet.gethostname() == {:ok, 'freebsd'} do
        {:expassword_algorithm, path: "~/elixir/expassword/expassword_algorithm"}
      else
        {:expassword_algorithm, ">= 0.0.0"}
      end,
      if :inet.gethostname() == {:ok, 'freebsd'} do
        {:bcrypt_elixir, path: "~/elixir/bcrypt_elixir", optional: true}
      else
        {:bcrypt_elixir, ">= 0.0.0"}
      end,
      if :inet.gethostname() == {:ok, 'freebsd'} do
        {:expassword_argon2, path: "~/elixir/expassword/expassword_argon2", optional: true}
      else
        {:expassword_argon2, ">= 0.0.0"}
      end,
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
    ]
  end
end
