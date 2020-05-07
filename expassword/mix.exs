defmodule ExPassword.MixProject do
  use Mix.Project

  def project do
    [
      app: :expassword,
      version: "0.1.0",
      elixir: "~> 1.6",
      start_permanent: Mix.env() == :prod,
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
        {:bcrypt_elixir, git: "https://github.com/julp/bcrypt_elixir.git", branch: "master", optional: true}
      end,
    ]
  end
end
