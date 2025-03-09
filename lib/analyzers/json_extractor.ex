
defmodule JSLurk.Analyzers.JSONExtractor do
  @moduledoc """
  Extracts JSON objects from JavaScript code.
  """

  @doc """
  Extracts JSON objects from text using various patterns.
  Returns a list of extracted JSON objects.
  """
  def extract_json(text) when is_binary(text) do
    # Try to find JSON objects in the text
    try do
      # Look for patterns that might indicate JSON objects
      extract_json_objects(text)
    rescue
      e -> 
        IO.puts("Error extracting JSON: #{inspect(e)}")
        []
    end
  end

  def extract_json(_), do: []

  # Extract JSON objects using various patterns
  defp extract_json_objects(text) do
    patterns = [
      ~r/\{[^{}]*"[^"]*"\s*:[^{}]*\}/,       # Simple JSON objects
      ~r/\[[^\[\]]*\{[^{}]*\}[^\[\]]*\]/,    # JSON arrays containing objects
      ~r/=\s*(\{.*?\})/s,                    # Variable assignments
      ~r/:\s*(\{.*?\})/s,                    # Object properties
      ~r/return\s+(\{.*?\})/s,               # Return statements
      ~r/\(\s*(\{.*?\})\s*\)/s               # Function arguments
    ]

    # Try each pattern and collect results
    Enum.flat_map(patterns, fn pattern ->
      Regex.scan(pattern, text)
      |> Enum.map(fn 
        [match | _] -> match
        match -> match
      end)
      |> Enum.filter(&valid_json?/1)
      |> Enum.map(&parse_json/1)
      |> Enum.reject(&is_nil/1)
    end)
  end

  # Check if a string is valid JSON
  defp valid_json?(str) do
    try do
      case Jason.decode(str) do
        {:ok, _} -> true
        _ -> false
      end
    rescue
      _ -> false
    end
  end

  # Parse JSON string to Elixir data structure
  defp parse_json(str) do
    try do
      case Jason.decode(str) do
        {:ok, parsed} -> parsed
        _ -> nil
      end
    rescue
      _ -> nil
    end
  end
end
