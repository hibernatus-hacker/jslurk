
defmodule Mix.Tasks.JsLurk do
  use Mix.Task

  @shortdoc "Runs the JSLurk JavaScript analyzer"
  def run(args) do
    # Ensure all dependencies are started
    Application.ensure_all_started(:httpoison)
    
    # Call your CLI module
    JSLurk.CLI.main(args)
  end
end
