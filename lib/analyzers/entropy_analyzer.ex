
defmodule JSLurk.Analyzers.EntropyAnalyzer do
  @moduledoc """
  Analyzes strings for entropy to detect potential secrets.
  """

  @spec analyze(String.t()) :: map()
  def analyze(string) when is_binary(string) do
    # Calculate entropy
    entropy = calculate_entropy(string)

    # Check against known secret patterns
    pattern_match = matches_secret_pattern?(string)

    %{
      entropy: entropy,
      is_secret: is_likely_secret?(entropy, pattern_match),
      confidence: calculate_confidence(entropy, pattern_match),
      pattern_match: pattern_match
    }
  end

  defp calculate_entropy(string) do
    string
    |> String.graphemes()
    |> Enum.frequencies()
    |> Map.values()
    |> Enum.map(fn count ->
      prob = count / String.length(string)
      -prob * :math.log2(prob)
    end)
    |> Enum.sum()
  end

  defp matches_secret_pattern?(string) do
    # Common API key patterns
    api_key_patterns = [
      ~r/AKIA[A-Z0-9]{16}/,           # AWS Access Key ID
      ~r/SK[a-zA-Z0-9]{32}/,          # Twilio API Key
      ~r/[a-z0-9_-]{16,64}\.[a-z0-9_-]{16,64}/, # JWT-like pattern
      ~r/[a-zA-Z0-9_\-]{32,}/         # Generic API key pattern
    ]

    Enum.any?(api_key_patterns, fn pattern ->
      String.match?(string, pattern)
    end)
  end

  defp is_likely_secret?(entropy, pattern_match) do
    # Higher entropy threshold for strings without matching patterns
    base_threshold = if pattern_match, do: 4.5, else: 5.0

    entropy >= base_threshold && !looks_like_obfuscated?(entropy)
  end

 defp looks_like_obfuscated?(entropy) do
    # Obfuscated code typically has very high entropy (> 6.0)
    # Base64 encoded strings usually have entropy around 5.3-5.5
    entropy > 6.0 || (entropy >= 5.3 && entropy <= 5.5)
  end

  defp calculate_confidence(entropy, pattern_match) do
    base_score = case entropy do
      e when e >= 5.5 -> 0.7
      e when e >= 5.0 -> 0.4
      _ -> 0.1
    end

    if pattern_match do
      base_score + 0.3
    else
      base_score
    end
    |> min(1.0)
  end

  # Add a function to scan for secrets in various data types
  def scan_for_secrets(data) when is_binary(data) do
    # For strings, analyze directly
    analyze(data)
  end

  def scan_for_secrets(data) when is_map(data) do
    # For maps (like JSON objects), analyze each value
    Enum.flat_map(data, fn {key, value} ->
      case scan_for_secrets(value) do
        %{is_secret: true} = result -> [%{key: key, value: value, analysis: result}]
        _ -> []
      end
    end)
  end

  def scan_for_secrets(data) when is_list(data) do
    # For lists, analyze each item
    Enum.flat_map(data, fn item ->
      case scan_for_secrets(item) do
        %{is_secret: true} = result -> [%{value: item, analysis: result}]
        items when is_list(items) -> items
        _ -> []
      end
    end)
  end

  def scan_for_secrets(_), do: []

  # Add a function to print the results
  def print_summary(secrets) do
    if Enum.empty?(secrets) do
      IO.puts("\n=== No Potential Secrets Found ===")
    else
      IO.puts("\n=== Potential Secrets Found (#{length(secrets)}) ===\n")

      # Group by confidence level
      grouped = Enum.group_by(secrets, fn
        %{analysis: %{confidence: conf}} ->
          cond do
            conf >= 0.8 -> :high
            conf >= 0.5 -> :medium
            true -> :low
          end
      end)

      # Print high confidence secrets first
      if high = grouped[:high] do
        IO.puts("High Confidence (#{length(high)}):")
        Enum.each(high, &print_secret/1)
        IO.puts("")
      end

      # Print medium confidence secrets
      if medium = grouped[:medium] do
        IO.puts("Medium Confidence (#{length(medium)}):")
        Enum.each(medium, &print_secret/1)
        IO.puts("")
      end

      # Print low confidence secrets (optional)
      if low = grouped[:low] do
        IO.puts("Low Confidence (#{length(low)}):")
        Enum.each(low, &print_secret/1)
      end

      IO.puts("\n=== End of Secrets Scan ===")
    end
  end

  defp print_secret(%{key: key, value: value, analysis: analysis}) do
    IO.puts("  - Key: #{key}")
    IO.puts("    Value: #{truncate(to_string(value), 60)}")
    IO.puts("    Entropy: #{Float.round(analysis.entropy, 2)}")
    IO.puts("    Confidence: #{Float.round(analysis.confidence * 100)}%")
    IO.puts("    Pattern Match: #{analysis.pattern_match}")
    IO.puts("")
  end

  defp print_secret(%{value: value, analysis: analysis}) do
    IO.puts("  - Value: #{truncate(to_string(value), 60)}")
    IO.puts("    Entropy: #{Float.round(analysis.entropy, 2)}")
    IO.puts("    Confidence: #{Float.round(analysis.confidence * 100)}%")
    IO.puts("    Pattern Match: #{analysis.pattern_match}")
    IO.puts("")
  end

  defp truncate(text, max_length) do
    if String.length(text) > max_length do
      String.slice(text, 0, max_length) <> "..."
    else
      text
    end
  end
end
