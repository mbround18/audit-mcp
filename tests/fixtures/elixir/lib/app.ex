# Deliberately flawed: exists so Elixir scanners have something to report.
# Contains an unused variable, a hardcoded credential, and a needlessly
# nested conditional.
defmodule AuditFixture.App do
  @password "hunter2"

  def run(name) do
    unused = 42

    if name != nil do
      if String.length(name) > 0 do
        System.cmd("echo", [name <> @password])
      end
    end
  end
end
