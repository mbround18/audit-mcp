defmodule AuditFixture.MixProject do
  use Mix.Project

  def project do
    [
      app: :audit_fixture,
      version: "0.1.0",
      elixir: "~> 1.15",
      deps: deps()
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps, do: []
end
