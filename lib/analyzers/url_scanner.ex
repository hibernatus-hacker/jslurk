
defmodule JSLurk.Analyzers.URLScanner do
  @moduledoc """
  A module for scanning and extracting URLs, relative URLs, and API endpoints from text.
  Particularly useful for analyzing JavaScript files.
  """

  @doc """
  Scans text for URLs and returns a map with categorized results.
  """
  def scan(text) when is_binary(text) do
    %{
      absolute_urls: extract_absolute_urls(text),
      relative_urls: extract_relative_urls(text),
      api_endpoints: extract_api_endpoints(text)
    }
  end

  @doc """
  Extracts absolute URLs (with http/https protocol) from text.
  """
  def extract_absolute_urls(text) when is_binary(text) do
    # Pattern for absolute URLs (http/https)
    pattern = ~r/(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))/

    Regex.scan(pattern, text)
    |> Enum.map(fn [match | _] -> match end)
    |> Enum.uniq()
  end

  @doc """
  Extracts relative URLs (starting with /) from text.
  """
  def extract_relative_urls(text) when is_binary(text) do
    # Pattern for relative URLs (starting with /)
    # This matches paths like /api/v1/users but not within absolute URLs
    pattern = ~r/(?<![a-zA-Z0-9])\/(?!\/)[a-zA-Z0-9_\-\/]+(?:\.[a-zA-Z0-9_\-]+)?(?:\?[^"'\s()<>]+)?/

    Regex.scan(pattern, text)
    |> Enum.map(fn [match | _] -> match end)
    |> Enum.uniq()
    |> Enum.filter(fn url -> 
      # Filter out URLs that are part of absolute URLs
      not Regex.match?(~r/https?:\/\/[^\/]+#{Regex.escape(url)}/, text)
    end)
  end

  @doc """
  Extracts potential API endpoints from text.
  This includes both absolute URLs and relative paths that look like API endpoints.
  """
  def extract_api_endpoints(text) when is_binary(text) do
    # Combine absolute URLs and relative URLs that look like API endpoints
    absolute_apis = extract_absolute_urls(text)
                    |> Enum.filter(&api_endpoint?/1)
    
    relative_apis = extract_relative_urls(text)
                    |> Enum.filter(&api_endpoint?/1)
    
    # Also look for patterns that suggest API calls
    api_patterns = [
      ~r/fetch\(['"]([^'"]+)['"]\)/,
      ~r/axios\.(?:get|post|put|delete|patch)\(['"]([^'"]+)['"]\)/,
      ~r/\$\.(?:get|post|ajax)\(['"]([^'"]+)['"]\)/,
      ~r/new XMLHttpRequest\(\).*\.open\(['"][A-Z]+['"],\s*['"]([^'"]+)['"]\)/s
    ]
    
    api_calls = Enum.flat_map(api_patterns, fn pattern ->
      Regex.scan(pattern, text)
      |> Enum.map(fn 
        [_, url] -> url
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)
    end)
    
    (absolute_apis ++ relative_apis ++ api_calls)
    |> Enum.uniq()
  end

  @doc """
  Determines if a URL is likely to be an API endpoint.
  """
  def api_endpoint?(url) when is_binary(url) do
    # Check for common API patterns
    Regex.match?(~r/(api|graphql|v\d+|rest|service|endpoint|\/[a-z]+\/[a-z0-9]+$)/, url) or
    # Check for common API file extensions
    Regex.match?(~r/\.(json|xml|graphql)($|\?)/, url) or
    # Check for query parameters that suggest API
    Regex.match?(~r/\?.*=.*(&.*=.*)*$/, url)
  end

  @doc """
  Prints a summary of found URLs to the console.
  """
  def print_summary(scan_results) do
    IO.puts("\n=== URL Scan Results ===\n")
    
    IO.puts("Absolute URLs (#{length(scan_results.absolute_urls)}):")
    Enum.each(scan_results.absolute_urls, &IO.puts("  - #{&1}"))
    
    IO.puts("\nRelative URLs (#{length(scan_results.relative_urls)}):")
    Enum.each(scan_results.relative_urls, &IO.puts("  - #{&1}"))
    
    IO.puts("\nAPI Endpoints (#{length(scan_results.api_endpoints)}):")
    Enum.each(scan_results.api_endpoints, &IO.puts("  - #{&1}"))
    
    IO.puts("\n=== End of Scan ===")
  end
end
