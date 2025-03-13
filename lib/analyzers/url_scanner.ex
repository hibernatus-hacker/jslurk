
defmodule JSLurk.Analyzers.URLScanner do
  @moduledoc """
  A module for scanning and extracting URLs, relative URLs, and API endpoints from client-side JavaScript.
  Optimized for bug bounty hunting in frontend JavaScript files.
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
  Enhanced to catch URLs in various JavaScript contexts.
  """
  def extract_absolute_urls(text) when is_binary(text) do
    # Pattern for absolute URLs (http/https) in various contexts
    patterns = [
      # Standard URLs
      ~r/(https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*))/,

      # URLs in string literals (single, double quotes, backticks)
      ~r/['"`](https?:\/\/[^'"`\s]+)['"`]/,

      # URLs in common client-side patterns
      ~r/\burl\s*:\s*['"`](https?:\/\/[^'"`]+)['"`]/i,
      ~r/\bsrc\s*=\s*['"`](https?:\/\/[^'"`]+)['"`]/i,
      ~r/\bhref\s*=\s*['"`](https?:\/\/[^'"`]+)['"`]/i,

      # URLs in fetch calls
      ~r/fetch\s*\(\s*['"`](https?:\/\/[^'"`]+)['"`]/i,

      # URLs in XHR
      ~r/\.open\s*\(\s*['"][A-Z]+['"],\s*['"`](https?:\/\/[^'"`]+)['"`]/i
    ]

    patterns
    |> Enum.flat_map(fn pattern ->
      Regex.scan(pattern, text)
      |> Enum.map(fn
        [_, url] -> url
        [url] -> url
      end)
    end)
    |> Enum.map(&clean_url/1)
    |> Enum.uniq()
    |> Enum.filter(&valid_url?/1)
  end

  @doc """
  Extracts relative URLs (starting with /) from text.
  Enhanced to catch URLs in various JavaScript contexts.
  """
  def extract_relative_urls(text) when is_binary(text) do
    # Patterns for relative URLs in various contexts
    patterns = [
      # Standard relative URLs
      ~r/(?<![a-zA-Z0-9])\/(?!\/)[a-zA-Z0-9_\-\/]+(?:\.[a-zA-Z0-9_\-]+)?(?:\?[^"'\s()<>]+)?/,

      # URLs in string literals
      ~r/['"`](\/[a-zA-Z0-9_\-\/][^'"`\s]*?)['"`]/,

      # URLs in common client-side patterns
      ~r/\burl\s*:\s*['"`](\/[^'"`]+)['"`]/i,
      ~r/\bsrc\s*=\s*['"`](\/[^'"`]+)['"`]/i,
      ~r/\bhref\s*=\s*['"`](\/[^'"`]+)['"`]/i,

      # URLs in fetch calls
      ~r/fetch\s*\(\s*['"`](\/[^'"`]+)['"`]/i,

      # URLs in XHR
      ~r/\.open\s*\(\s*['"][A-Z]+['"],\s*['"`](\/[^'"`]+)['"`]/i
    ]

    patterns
    |> Enum.flat_map(fn pattern ->
      Regex.scan(pattern, text)
      |> Enum.map(fn
        [_, url] -> url
        [url] -> url
      end)
    end)
    |> Enum.map(&clean_url/1)
    |> Enum.uniq()
    |> Enum.filter(fn url ->
      # Filter out URLs that are part of absolute URLs
      not Regex.match?(~r/https?:\/\/[^\/]+#{Regex.escape(url)}/, text) and
      # Filter out common false positives
      not Regex.match?(~r/^\/\//, url) and
      # Ensure it starts with /
      String.starts_with?(url, "/")
    end)
  end

  @doc """
  Validates if a string is likely a URL.
  """
  def valid_url?(url) when is_binary(url) do
    cond do
      # Absolute URL
      Regex.match?(~r/^https?:\/\//, url) -> true
      # Relative URL
      String.starts_with?(url, "/") -> true
      # Likely not a URL
      true -> false
    end
  end


  @doc """
  Determines if a URL is likely to be an API endpoint.
  Enhanced with more patterns specific to client-side APIs.
  """
  def api_endpoint?(url) when is_binary(url) do
    # Check for common API patterns
    Regex.match?(~r/(api|graphql|v\d+|rest|service|endpoint|data|proxy|\/[a-z]+\/[a-z0-9]+$)/, url) or
    # Check for common API file extensions
    Regex.match?(~r/\.(json|xml|graphql|jsonp)($|\?)/, url) or
    # Check for query parameters that suggest API
    Regex.match?(~r/\?.*=.*(&.*=.*)*$/, url) or
    # Check for patterns common in REST APIs
    Regex.match?(~r/(\/users\/|\/posts\/|\/comments\/|\/products\/|\/search)/, url)
  end

 @doc """
  Cleans a URL by removing surrounding quotes and trimming whitespace.
  """
  def clean_url(url) when is_binary(url) do
    url
    |> String.trim()
    |> String.trim_leading(~s("'))
    |> String.trim_leading(~s(`))
    |> String.trim_trailing(~s("'))
    |> String.trim_trailing(~s(`))
    |> String.split(~r/['"`]/, parts: 2)
    |> List.first()
  end

  @doc """
  Extracts potential API endpoints from text.
  Focuses on client-side API calls.
  """
  def extract_api_endpoints(text) when is_binary(text) do
    # Combine absolute URLs and relative URLs that look like API endpoints
    absolute_apis = extract_absolute_urls(text)
                    |> Enum.filter(&api_endpoint?/1)

    relative_apis = extract_relative_urls(text)
                    |> Enum.filter(&api_endpoint?/1)

    # Patterns that suggest API calls in client-side JavaScript
    api_patterns = [
      # Fetch API
      ~r/fetch\s*\(\s*['"`]([^'"`]+)['"`]/i,

      # XMLHttpRequest
      ~r/\.open\s*\(\s*['"][A-Z]+['"],\s*['"`]([^'"`]+)['"`]/i,

      # jQuery AJAX
      ~r/\$\.(?:get|post|ajax)\s*\(\s*['"`]([^'"`]+)['"`]/i,

      # Common client-side API configurations
      ~r/\bapiUrl\s*[=:]\s*['"`]([^'"`]+)['"`]/i,
      ~r/\bendpoint\s*[=:]\s*['"`]([^'"`]+)['"`]/i,
      ~r/\bbaseUrl\s*[=:]\s*['"`]([^'"`]+)['"`]/i,

      # GraphQL endpoints
      ~r/graphql(?:Url|Endpoint)?\s*[=:]\s*['"`]([^'"`]+)['"`]/i
    ]

    api_calls = Enum.flat_map(api_patterns, fn pattern ->
      Regex.scan(pattern, text)
      |> Enum.map(fn
        [_, url] -> url
        _ -> nil
      end)
      |> Enum.reject(&is_nil/1)
      |> Enum.filter(fn url ->
        # Filter out non-URL strings
        String.contains?(url, "/") or String.contains?(url, ".")
      end)
    end)
  end
end


