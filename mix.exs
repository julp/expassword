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
      deps: deps(),
      dialyzer: [plt_add_apps: ~W[mix ex_unit]a],
      description: description(),
      package: package(),
      source_url: "https://github.com/julp/expassword",
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: ~W[logger]a
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:expassword_algorithm, "~> 0.1"},
      {:expassword_bcrypt, "~> 0.1", optional: true},
      {:expassword_argon2, "~> 0.1", optional: true},
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
      {:dialyxir, "~> 1.1", only: ~W[dev test]a, runtime: false},
    ]
  end

  defp description() do
    ~S"""
    This is a "port" of PHP password\_\* functions, an abstraction layer on top of supported algorithms (bcrypt and argon2).
    """
  end

  defp package() do
    [
      files: ~W[lib mix.exs README*],
      licenses: ~W[BSD],
      links: %{"GitHub" => "https://github.com/julp/expassword"},
    ]
  end
end
