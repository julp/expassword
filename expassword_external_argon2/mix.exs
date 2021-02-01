defmodule ExPassword.ExternalArgon2.MixProject do
  use Mix.Project

  def project do
    [
      app: :expassword_external_argon2,
      version: "0.1.0",
      elixir: "~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      test_paths: ~W[../expassword_argon2/test],
      deps: deps()
    ]
  end

  # Configuration for the OTP application.
  #
  # Type `mix help compile.app` for more information.
  def application do
    [
      extra_applications: [:logger, :runtime_tools]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ~W[lib ../expassword_argon2/test/support]
  defp elixirc_paths(_), do: ~W[lib]

  # Specifies your project dependencies.
  #
  # Type `mix help deps` for examples and options.
  defp deps do
    [
      if :inet.gethostname() == {:ok, 'freebsd'} do
        {:expassword_algorithm, path: "~/elixir/expassword/expassword_algorithm"}
      else
        {:expassword_algorithm, "~> 0.1.0"}
      end,
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
    ]
  end
end
