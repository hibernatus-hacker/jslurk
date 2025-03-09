# lib/jslurk/scanner.ex
defmodule JSLurk.Scanner do
  @moduledoc """
  Handles the scanning of JavaScript files for interesting information.
  """

  alias JSLurk.Analyzers.{
    EntropyAnalyzer,
    JSONExtractor,
    URLScanner,
    DOMSecurityScanner
  }

  def scan_url(url, verbose \\ false) do
    IO.puts("Scanning #{url}...")

    case HTTPoison.get(url, [], [
      timeout: 10000,
      recv_timeout: 10000,
      follow_redirect: true,
      max_redirect: 5
    ]) do
      {:ok, response} ->
        if verbose do
          IO.puts("Successfully requested #{url} - Status: #{response.status_code}")
        end

        # First scan the content
        result = scan_content(url, response.body, response.status_code)
        # Then add the content to the result
        Map.put(result, :content, response.body)

      {:error, %HTTPoison.Error{reason: reason}} ->
        error_message = format_error(reason)
        IO.puts("Error requesting #{url}: #{error_message}")

        %{
          url: url,
          status: :error,
          error: error_message,
          timestamp: DateTime.utc_now() |> DateTime.to_iso8601()
        }
    end
  end

  def scan_content(url, content, status_code) do
    # Extract JSON from the content
    json_objects = JSONExtractor.extract_json(content)

    # Scan for URLs in the content
    url_scan_results = URLScanner.scan(content)

    # Scan for DOM security issues
    dom_scan_results = DOMSecurityScanner.scan(content)

    # Scan for potential secrets
    secrets = []

    # Check JSON objects for secrets
    json_secrets = Enum.flat_map(json_objects, &EntropyAnalyzer.scan_for_secrets/1)
    secrets = secrets ++ json_secrets

    # Check URLs for secrets (API keys in query params, etc.)
    url_secrets = Enum.flat_map(url_scan_results.api_endpoints, fn endpoint_url ->
      # Extract query parameters if present
      case String.split(endpoint_url, "?", parts: 2) do
        [_, query] ->
          # Split query into key-value pairs
          String.split(query, "&")
          |> Enum.map(fn param ->
            case String.split(param, "=", parts: 2) do
              [key, value] ->
                analysis = EntropyAnalyzer.analyze(value)
                if analysis.is_secret do
                  %{key: key, value: value, analysis: analysis}
                else
                  nil
                end
              _ -> nil
            end
          end)
          |> Enum.reject(&is_nil/1)
        _ -> []
      end
    end)
    secrets = secrets ++ url_secrets

    %{
      url: url,
      status: status_code,
      timestamp: DateTime.utc_now() |> DateTime.to_iso8601(),
      json_objects: length(json_objects),
      urls: %{
        absolute: length(url_scan_results.absolute_urls),
        relative: length(url_scan_results.relative_urls),
        api_endpoints: length(url_scan_results.api_endpoints)
      },
      dom_security: %{
        manipulations: length(dom_scan_results.dom_manipulations),
        templates: length(dom_scan_results.html_templates),
        sinks: length(dom_scan_results.dom_sinks),
        sensitive_comments: Enum.count(dom_scan_results.comments, & &1.sensitive)
      },
      secrets: length(secrets),
      details: %{
        json_objects: json_objects,
        urls: url_scan_results,
        dom_security: dom_scan_results,
        secrets: secrets
      }
    }
  end

  defp format_error(reason) do
    case reason do
      {:max_redirect_overflow, _} -> "Too many redirects"
      :timeout -> "Connection timeout"
      :connect_timeout -> "Connection timeout"
      {:tls_alert, _} -> "TLS/SSL error"
      _ -> inspect(reason)
    end
  end
end
