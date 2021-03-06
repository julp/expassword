defmodule ExpasswordAlgorithm.MixProject do
  use Mix.Project

  def project do
    [
      app: :expassword_algorithm,
      version: "0.1.0",
      elixir: "~> 1.10",
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
      {:earmark, "~> 1.4", only: :dev},
      {:ex_doc, "~> 0.22", only: :dev},
    ]
  end
end
