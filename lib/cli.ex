
defmodule JSLurk.CLI do
  @moduledoc """
  Command-line interface for JSLurk.
  """

  alias JSLurk.{Scanner, Formatter, Downloader}

  @banner """
  ╔═══════════════════════════════════════════════════════════════╗
  ║                                                               ║
  ║   JSLurk                                                      ║
  ║   A tool for analysing javascript files                       ║
  ║   @author : hibernatus                                        ║
  ║                                                               ║
  ╚═══════════════════════════════════════════════════════════════╝
  """

  def main(args) do
    IO.puts(@banner)

    args
    |> parse_args()
    |> process()
  end

  defp parse_args(args) do
    {opts, urls, _} =
      OptionParser.parse(args,
        strict: [
          domains: :string,
          help: :boolean,
          verbose: :boolean,
          output: :string,
          download: :string
        ],
        aliases: [
          d: :domains,
          h: :help,
          v: :verbose,
          o: :output,
          D: :download
        ]
      )

    {opts, urls}
  end

  defp process({opts, []}) do
    cond do
      opts[:help] ->
        print_help()

      opts[:domains] ->
        opts[:domains]
        |> File.read!()
        |> String.split("\n", trim: true)
        |> scan_urls(opts)

      true ->
        # Read from stdin (pipe)
        IO.read(:stdio, :eof)
        |> String.split("\n", trim: true)
        |> scan_urls(opts)
    end
  end

  defp process({opts, urls}) do
    scan_urls(urls, opts)
  end

 defp scan_urls(urls, opts) do
    verbose = Keyword.get(opts, :verbose, false)
    output_file = Keyword.get(opts, :output, nil)
    download_dir = Keyword.get(opts, :download, nil)

    # Process each URL and print results immediately
    results =
      urls
      |> Enum.map(fn url ->
        # Get the scan result
        result = Scanner.scan_url(url, verbose)

        # Handle downloads if needed
        result_without_content =
          if download_dir && Map.has_key?(result, :content) do
            Downloader.save(url, result[:content], download_dir)
            Map.delete(result, :content)
          else
            result
          end

        # Handle output file if specified
        # Print the result immediately if no output file is specified
        if output_file == nil do
          print_single_result(result_without_content)
        end

        # Return the result for collection
        result_without_content
      end)

    if output_file do
      # Truncate string values in the results before encoding to JSON
      truncated_results = truncate_values_for_json(results)

      # Add metadata about truncation
      final_output = %{
        metadata: %{
          truncated: true,
          max_string_length: 300,
          generated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
          note: "String values longer than 300 characters have been truncated to reduce file size."
        },
        results: truncated_results
      }

      File.write!(output_file, Jason.encode!(final_output, pretty: true))
      IO.puts("Results saved to #{output_file} (with values truncated to 300 characters)")
    end

#     # Handle output file if specified
#     if output_file do
#       File.write!(output_file, Jason.encode!(results, pretty: true))
#       IO.puts("Results saved to #{output_file}")
#     end

    # Always print the summary
    Formatter.print_summary(results)
  end

  @doc """
  Recursively truncates all string values in a data structure to a maximum length.
  Preserves certain fields like URLs and keys without truncation.
  """
  def truncate_values_for_json(data, max_length \\ 300) do
    # Define non-truncated keys
    non_truncated_keys = ["url", "key", "type", "timestamp"]

    # Helper function to truncate a single value
    truncate_value = fn value, key ->
      if is_binary(value) && String.length(value) > max_length && !Enum.member?(non_truncated_keys, key) do
        String.slice(value, 0, max_length) <> "... (truncated)"
      else
        value
      end
    end

    # Recursive function to process the data structure
    process_data = fn data, func ->
      cond do
        # For maps, recursively process each value
        is_map(data) ->
          data
          |> Enum.map(fn {k, v} ->
            # If the value is a complex data structure, recurse
            new_v = cond do
              is_map(v) -> func.(v, func)
              is_list(v) -> func.(v, func)
              true -> truncate_value.(v, k)
            end
            {k, new_v}
          end)
          |> Enum.into(%{})

        # For lists, recursively process each item
        is_list(data) ->
          Enum.map(data, fn v ->
            cond do
              is_map(v) -> func.(v, func)
              is_list(v) -> func.(v, func)
              is_binary(v) -> truncate_value.(v, "")
              true -> v
            end
          end)

        # For other values, return as is
        true -> data
      end
    end

    # Start the recursive processing
    process_data.(data, process_data)
  end

  # New function to print a single result
  defp print_single_result(result) do
    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("URL: #{result.url}")
    IO.puts("Status: #{result.status}")
    IO.puts("Timestamp: #{result.timestamp}")

    # Print JSON objects if any were found
    if result.json_objects > 0 do
      IO.puts("\nJSON Objects (#{result.json_objects}):")
      print_json_objects(result.details.json_objects)
    end

    # Print URLs if any were found
    if result.urls.absolute > 0 || result.urls.relative > 0 || result.urls.api_endpoints > 0 do
      IO.puts("\nURLs:")
      print_urls(result.details.urls)
    end

    # Print DOM security issues if any were found
    if result.dom_security.manipulations > 0 ||
       result.dom_security.templates > 0 ||
       result.dom_security.sinks > 0 ||
       result.dom_security.sensitive_comments > 0 do
      IO.puts("\nDOM Security Issues:")
      print_dom_security(result.details.dom_security)
    end

    # Print secrets if any were found
    if result.secrets > 0 do
      IO.puts("\nPotential Secrets (#{result.secrets}):")
      print_secrets(result.details.secrets)
    end

    IO.puts(String.duplicate("=", 80))
  end


  # Helper function to print JSON objects
  defp print_json_objects(json_objects) do
    # Limit to first 5 objects to avoid overwhelming the console
    Enum.take(json_objects, 5)
    |> Enum.with_index(1)
    |> Enum.each(fn {obj, index} ->
      json_preview = Jason.encode!(obj, pretty: true)
                    |> String.split("\n")
                    |> Enum.take(3)
                    |> Enum.join("\n")
                    |> then(fn preview ->
                         if String.length(preview) > 300, do: String.slice(preview, 0, 300) <> "...", else: preview
                       end)

      IO.puts("    #{index}. Size: #{byte_size(Jason.encode!(obj))} bytes")
      IO.puts("       Preview: #{json_preview}")
    end)

    if length(json_objects) > 5 do
      IO.puts("    ... and #{length(json_objects) - 5} more")
    end
  end

  # Helper function to print URLs
  defp print_urls(urls) do
    if length(urls.absolute_urls) > 0 do
      IO.puts("    Absolute URLs (#{length(urls.absolute_urls)}):")
      Enum.take(urls.absolute_urls, 5)
      |> Enum.each(fn url -> IO.puts("      - #{url}") end)

      if length(urls.absolute_urls) > 5 do
        IO.puts("      ... and #{length(urls.absolute_urls) - 5} more")
      end
    end

    if length(urls.relative_urls) > 0 do
      IO.puts("    Relative URLs (#{length(urls.relative_urls)}):")
      Enum.take(urls.relative_urls, 5)
      |> Enum.each(fn url -> IO.puts("      - #{url}") end)

      if length(urls.relative_urls) > 5 do
        IO.puts("      ... and #{length(urls.relative_urls) - 5} more")
      end
    end

    if length(urls.api_endpoints) > 0 do
      IO.puts("    API Endpoints (#{length(urls.api_endpoints)}):")
      Enum.take(urls.api_endpoints, 5)
      |> Enum.each(fn url -> IO.puts("      - #{url}") end)

      if length(urls.api_endpoints) > 5 do
        IO.puts("      ... and #{length(urls.api_endpoints) - 5} more")
      end
    end
  end

  # Helper function to print DOM security issues
  defp print_dom_security(dom_security) do
    if length(dom_security.dom_manipulations) > 0 do
      IO.puts("    DOM Manipulations (#{length(dom_security.dom_manipulations)}):")
      Enum.take(dom_security.dom_manipulations, 3)
      |> Enum.each(fn item ->
        IO.puts("      - [Line #{item.line}] #{item.type}: #{truncate(item.code, 60)}")
      end)

      if length(dom_security.dom_manipulations) > 3 do
        IO.puts("      ... and #{length(dom_security.dom_manipulations) - 3} more")
      end
    end

    if length(dom_security.dom_sinks) > 0 do
      IO.puts("    DOM Sinks (#{length(dom_security.dom_sinks)}):")
      Enum.take(dom_security.dom_sinks, 3)
      |> Enum.each(fn item ->
        IO.puts("      - [Line #{item.line}] #{item.type} (Risk: #{item.risk}): #{truncate(item.code, 60)}")
      end)

      if length(dom_security.dom_sinks) > 3 do
        IO.puts("      ... and #{length(dom_security.dom_sinks) - 3} more")
      end
    end

    sensitive_comments = Enum.filter(dom_security.comments, & &1.sensitive)
    if length(sensitive_comments) > 0 do
      IO.puts("    Sensitive Comments (#{length(sensitive_comments)}):")
      Enum.take(sensitive_comments, 3)
      |> Enum.each(fn item ->
        IO.puts("      - [Line #{item.line}] #{truncate(item.content, 60)}")
      end)

      if length(sensitive_comments) > 3 do
        IO.puts("      ... and #{length(sensitive_comments) - 3} more")
      end
    end
  end

  # Helper function to print secrets
  defp print_secrets(secrets) do
    # Group by confidence level
    grouped = Enum.group_by(secrets, fn
      %{analysis: %{confidence: conf}} ->
        cond do
          conf >= 0.8 -> :high
          conf >= 0.5 -> :medium
          true -> :low
        end
      _ -> :unknown
    end)

    # Print high confidence secrets first
    if high = grouped[:high] do
      IO.puts("    High Confidence (#{length(high)}):")
      Enum.take(high, 3)
      |> Enum.each(&print_secret_item/1)

      if length(high) > 3 do
        IO.puts("      ... and #{length(high) - 3} more")
      end
    end

    # Print medium confidence secrets
    if medium = grouped[:medium] do
      IO.puts("    Medium Confidence (#{length(medium)}):")
      Enum.take(medium, 3)
      |> Enum.each(&print_secret_item/1)

      if length(medium) > 3 do
        IO.puts("      ... and #{length(medium) - 3} more")
      end
    end

    # Print low confidence secrets (limited)
    if low = grouped[:low] do
      IO.puts("    Low Confidence (#{length(low)}):")
      Enum.take(low, 2)
      |> Enum.each(&print_secret_item/1)

      if length(low) > 2 do
        IO.puts("      ... and #{length(low) - 2} more")
      end
    end
  end

  # Helper function to print a single secret item
  defp print_secret_item(%{key: key, value: value, analysis: analysis}) do
    IO.puts("      - Key: #{key}")
    IO.puts("        Value: #{truncate(to_string(value), 40)}")
    IO.puts("        Entropy: #{Float.round(analysis.entropy, 2)}")
    IO.puts("        Confidence: #{Float.round(analysis.confidence * 100)}%")
  end

  defp print_secret_item(%{value: value, analysis: analysis}) do
    IO.puts("      - Value: #{truncate(to_string(value), 40)}")
    IO.puts("        Entropy: #{Float.round(analysis.entropy, 2)}")
    IO.puts("        Confidence: #{Float.round(analysis.confidence * 100)}%")
  end

  # Helper function to truncate text
  defp truncate(text, max_length) do
    if String.length(text) > max_length do
      String.slice(text, 0, max_length) <> "..."
    else
      text
    end
  end

  defp print_help do
    IO.puts("""
    JSLurk - A tool for analysing javascript files

    Usage:
      jslurk [options] [URLs...]
      cat domains.txt | jslurk

    Options:
      -d, --domains FILE    Read URLs from a file
      -o, --output FILE     Save results to a JSON file
      -v, --verbose         Show verbose output
      -h, --help            Show this help message

    Examples:
      jslurk https://example.com/script.js
      jslurk -d domains.txt
      cat domains.txt | jshound
    """)
  end
end
