# Deliberately flawed: exists so Ruby scanners have something to report.
# Uses a swallowed exception, a long line, and string interpolation into a
# shell command.
require 'rack'

class App
  PASSWORD = 'hunter2'

  def run( name )
    begin
      system("echo #{name}")
    rescue
    end
    puts "this line is deliberately far longer than the eighty character limit that rubocop enforces by default"
  end
end
