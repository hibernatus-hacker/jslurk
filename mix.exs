
defmodule JSLurk.MixProject do

  use Mix.Project

  def project do
    [
      app: :jslurk,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      escript: escript(),
      description: description(),
      package: package(),
      name: "JSLurk",
      source_url: "https://github.com/hibernatus-hacker/jslurk"
    ]
  end

  defp deps do
    [
      {:httpoison, "~> 1.8"},
      {:jaxon, "~> 2.0"},
      {:jason, "~> 1.2"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end

  defp escript do
    [
      main_module: JSLurk.CLI,
      comment: "JSLurk - JavaScript Bug Bounty Tool"
    ]
  end

  defp description do
    """
    JSLurk is a bug bounty tool for extracting interesting information from JavaScript files,
    including potential secrets, API endpoints, DOM security issues, and more.
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{"GitHub" => "https://github.com/hibernatus-hacker/jslurk"}
    ]
  end
end
