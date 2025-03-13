
defmodule JSLurk.CLI do
  @moduledoc """
  Command-line interface for JSLurk.
  """

  alias JSLurk.{Scanner, Formatter, Downloader}

  @banner """
  ╔═══════════════════════════════════════════════════════════════=╗
  ║                                                                ║
  ║ JSLurk                                                         ║
  ║ A tool for scanning javascript files for interesting tidbits.  ║
  ║ @author : hibernatus                                           ║
  ║                                                                ║
  ╚═══════════════════════════════════════════════════════════════=╝
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
        # For file input, we'll still process in batch
        opts[:domains]
        |> File.read!()
        |> String.split("\n", trim: true)
        |> scan_urls(opts)

      true ->
        # Process stdin URLs in real-time
        IO.puts("Reading and processing URLs from stdin in real-time...")

        # Process each URL as it arrives
        all_results = process_stdin_urls_realtime(opts)

        # Print summary at the end
        if length(all_results) > 0 do
          IO.puts("\nProcessed #{length(all_results)} URLs from stdin")

          # Handle output file if specified
          handle_output_file(opts, all_results)

          # Always print the summary with all results
          Formatter.print_summary(all_results)
        else
          IO.puts("No URLs found from stdin. Please provide URLs or use --help for more information.")
        end
    end
  end

  # Process URLs from stdin in real-time
  defp process_stdin_urls_realtime(opts) do
    # Initialize counters and accumulators
    patience_seconds = 30
    process_urls_with_patience(opts, [], 0, 0, patience_seconds)
  end

  # Process URLs with patience
  defp process_urls_with_patience(opts, results_acc, elapsed_seconds, url_count, max_patience) when elapsed_seconds >= max_patience do
    # We've reached the maximum wait time
    IO.puts("Reached maximum wait time of #{max_patience} seconds")
    Enum.reverse(results_acc)
  end

  defp process_urls_with_patience(opts, results_acc, elapsed_seconds, url_count, max_patience) do
    # Show waiting message occasionally
    if url_count == 0 && rem(elapsed_seconds, 10) == 0 && elapsed_seconds > 0 do
      IO.puts("Waited #{elapsed_seconds} seconds, no URLs yet...")
    end

    # Try to read a line with a 1-second timeout
    case read_line_with_timeout(1000) do
      {:ok, line} ->
        # Got a line, check if it's a URL
        clean_line = String.trim(line)

        if String.match?(clean_line, ~r/^https?:\/\//) do
          # Process this URL immediately
          IO.puts("\nProcessing URL: #{clean_line}")
          result = process_single_url(clean_line, opts)

          # Continue with updated state
          process_urls_with_patience(opts, [result | results_acc], 0, url_count + 1, max_patience)
        else
          # Not a URL, keep waiting
          process_urls_with_patience(opts, results_acc, elapsed_seconds, url_count, max_patience)
        end

      :timeout ->
        # No input for 1 second, increment counter and try again
        process_urls_with_patience(opts, results_acc, elapsed_seconds + 1, url_count, max_patience)

      :eof ->
        # End of file reached
        if url_count > 0 do
          IO.puts("End of input reached after processing #{url_count} URLs")
        else
          IO.puts("End of input reached with no URLs found")
        end
        Enum.reverse(results_acc)
    end
  end

  # Process a single URL and return its result
  defp process_single_url(url, opts) do
    verbose = Keyword.get(opts, :verbose, false)
    download = Keyword.get(opts, :download, false)
    download_dir = Keyword.get(opts, :download_dir, "downloads")
    output_file = Keyword.get(opts, :output, nil)

    # Get the scan result
    result = Scanner.scan_url(url, verbose)

    # Handle downloads if needed
    result_without_content =
      if download && Map.has_key?(result, :content) do
        Downloader.save(url, result[:content], download_dir)
        Map.delete(result, :content)
      else
        result
      end

    # Print the result immediately if no output file is specified
    if output_file == nil do
      if result_without_content[:status] == :error || Map.has_key?(result_without_content, :error) do
        print_error_result(result_without_content)
      else
        print_single_result(result_without_content)
      end
    end

    # Return the result for collection
    result_without_content
  end

  # Helper to print error results
  defp print_error_result(result) do
    IO.puts("\n" <> String.duplicate("=", 80))
    IO.puts("URL: #{result.url}")
    IO.puts("Status: ERROR")
    IO.puts("Error: #{Map.get(result, :error, "Unknown error")}")
    IO.puts("Timestamp: #{result.timestamp}")
    IO.puts(String.duplicate("=", 80))
  end

  # Helper to handle output file
  defp handle_output_file(opts, results) do
    output_file = Keyword.get(opts, :output, nil)

    if output_file do
      # Separate successful and error results for metadata
      {success_results, error_results} = Enum.split_with(results, fn result ->
        result[:status] != :error && !Map.has_key?(result, :error)
      end)

      # Prepare all results for JSON output
      json_ready_results = results |> truncate_values_for_json()

      # Add metadata about truncation
      final_output = %{
        metadata: %{
          truncated: true,
          max_string_length: 300,
          generated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
          note: "String values longer than 300 characters have been truncated to reduce file size.",
          success_count: length(success_results),
          error_count: length(error_results)
        },
        results: json_ready_results
      }

      File.write!(output_file, Jason.encode!(final_output, pretty: true))
      IO.puts("Results saved to #{output_file} (with values truncated to 300 characters)")
    end
  end

  defp read_line_with_timeout(timeout) do
    # Create a task that reads a line
    task = Task.async(fn -> IO.gets("") end)

    # Wait for the task with timeout
    case Task.yield(task, timeout) do
      {:ok, :eof} ->
        :eof

      {:ok, {:error, _reason}} ->
        :eof

      {:ok, line} ->
        {:ok, line}

      nil ->
        # Task didn't complete within timeout
        Task.shutdown(task)
        :timeout
    end
  end

 defp scan_urls(urls, opts) do
    verbose = Keyword.get(opts, :verbose, false)
    output_file = Keyword.get(opts, :output, nil)
    download = Keyword.get(opts, :download, false)
    download_dir = Keyword.get(opts, :download_dir, "downloads")

    # Process each URL and print results immediately
    all_results =
      urls
      |> Enum.map(fn url ->
        # Get the scan result
        result = Scanner.scan_url(url, verbose)

        # Handle downloads if needed
        result_without_content =
          if download && Map.has_key?(result, :content) do
            Downloader.save(url, result[:content], download_dir)
            Map.delete(result, :content)
          else
            result
          end

        # Print the result immediately if no output file is specified
        if output_file == nil do
          # Check if this is an error result
          if result_without_content[:status] == :error || Map.has_key?(result_without_content, :error) do
            IO.puts("\n" <> String.duplicate("=", 80))
            IO.puts("URL: #{result_without_content.url}")
            IO.puts("Status: ERROR")
            IO.puts("Error: #{Map.get(result_without_content, :error, "Unknown error")}")
            IO.puts("Timestamp: #{result_without_content.timestamp}")
            IO.puts(String.duplicate("=", 80))
          else
            # Print successful result
            print_single_result(result_without_content)
          end
        end

        # Return the result for collection
        result_without_content
      end)

    # Handle output file if specified
    if output_file do
      # Separate successful and error results for metadata
      {success_results, error_results} = Enum.split_with(all_results, fn result ->
        result[:status] != :error && !Map.has_key?(result, :error)
      end)

      # Prepare all results for JSON output
#       json_ready_results = all_results |> truncate_values_for_json()

      # Add metadata about truncation
      final_output = %{
        metadata: %{
          truncated: true,
          max_string_length: 300,
          generated_at: DateTime.utc_now() |> DateTime.to_iso8601(),
          note: "String values longer than 300 characters have been truncated to reduce file size.",
          success_count: length(success_results),
          error_count: length(error_results)
        },
        results: all_results
      }

      File.write!(output_file, Jason.encode!(final_output, pretty: true))
      IO.puts("Results saved to #{output_file} (with values truncated to 300 characters)")
    end

    # Always print the summary with all results
    Formatter.print_summary(all_results)
  end

  # Simplified function to print a single successful result
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

  @doc """
  Recursively truncates all string values in a data structure to a maximum length.
  Preserves certain fields like URLs and keys without truncation.
  """
  def truncate_values_for_json(data, max_length \\ 300) do
    # Define non-truncated keys
    non_truncated_keys = ["url", "key", "type", "timestamp", "error"]

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

  # Helper function to print JSON objects
  defp print_json_objects(json_objects) do
    Enum.with_index(json_objects, 1)
    |> Enum.each(fn {obj, index} ->
      json_preview = Jason.encode!(obj, pretty: true)
                    |> String.split("\n")
                    |> Enum.join("\n")

      IO.puts("    #{index}. Size: #{byte_size(Jason.encode!(obj))} bytes")
      IO.puts("       Preview: #{json_preview}")
    end)
  end

  # Helper function to print URLs
  defp print_urls(urls) do
    if length(urls.absolute_urls) > 0 do
      IO.puts("    Absolute URLs (#{length(urls.absolute_urls)}):")
      Enum.each(urls.absolute_urls, fn url -> IO.puts("      - #{url}") end)
    end

    if length(urls.relative_urls) > 0 do
      IO.puts("    Relative URLs (#{length(urls.relative_urls)}):")
      Enum.each(urls.relative_urls, fn url -> IO.puts("      - #{url}") end)
    end

    if length(urls.api_endpoints) > 0 do
      IO.puts("    API Endpoints (#{length(urls.api_endpoints)}):")
      Enum.each(urls.api_endpoints, fn url -> IO.puts("      - #{url}") end)
    end
  end

  # Helper function to print DOM security issues
  defp print_dom_security(dom_security) do
    if length(dom_security.dom_manipulations) > 0 do
      IO.puts("    DOM Manipulations (#{length(dom_security.dom_manipulations)}):")
      Enum.each(dom_security.dom_manipulations, fn item ->
        IO.puts("      - [Line #{item.line}] #{item.type}: #{truncate(item.code, 60)}")
      end)
    end

    if length(dom_security.dom_sinks) > 0 do
      IO.puts("    DOM Sinks (#{length(dom_security.dom_sinks)}):")
      Enum.each(dom_security.dom_sinks, fn item ->
        IO.puts("      - [Line #{item.line}] #{item.type} (Risk: #{item.risk}): #{truncate(item.code, 60)}")
      end)
    end

    sensitive_comments = Enum.filter(dom_security.comments, & &1.sensitive)
    if length(sensitive_comments) > 0 do
      IO.puts("    Sensitive Comments (#{length(sensitive_comments)}):")
      Enum.each(sensitive_comments, fn item ->
        IO.puts("      - [Line #{item.line}] #{truncate(item.content, 60)}")
      end)
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
      Enum.each(high, &print_secret_item/1)
    end

    # Print medium confidence secrets
    if medium = grouped[:medium] do
      IO.puts("    Medium Confidence (#{length(medium)}):")
      Enum.each(medium, &print_secret_item/1)
    end

    # Print low confidence secrets
    if low = grouped[:low] do
      IO.puts("    Low Confidence (#{length(low)}):")
      Enum.each(low, &print_secret_item/1)
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
