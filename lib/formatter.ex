# lib/JSLurk/formatter.ex
defmodule JSLurk.Formatter do
  @moduledoc """
  Handles formatting and displaying scan results.
  """

  def print_summary(results) do
    IO.puts("\n=== Summary ===\n")

    # Count successful and failed scans
    successful = Enum.count(results, fn r -> !Map.has_key?(r, :error) && r[:status] != :error end)
    failed = Enum.count(results) - successful

    IO.puts("Total URLs scanned: #{length(results)}")
    IO.puts("Successful scans: #{successful}")
    IO.puts("Failed scans: #{failed}")

    # Only process successful scans for the summary
    successful_results = Enum.filter(results, fn r -> !Map.has_key?(r, :error) && r[:status] != :error end)

    if successful > 0 do
      # Count findings
      total_json = Enum.reduce(successful_results, 0, fn r, acc -> acc + Map.get(r, :json_objects, 0) end)
      total_urls = Enum.reduce(successful_results, 0, fn r, acc ->
        urls = Map.get(r, :urls, %{absolute: 0, relative: 0, api_endpoints: 0})
        acc + urls.absolute + urls.relative + urls.api_endpoints
      end)
      total_api_endpoints = Enum.reduce(successful_results, 0, fn r, acc ->
        urls = Map.get(r, :urls, %{api_endpoints: 0})
        acc + urls.api_endpoints
      end)
      total_secrets = Enum.reduce(successful_results, 0, fn r, acc -> acc + Map.get(r, :secrets, 0) end)

      IO.puts("\nFindings:")
      IO.puts("  JSON Objects: #{total_json}")
      IO.puts("  URLs: #{total_urls}")
      IO.puts("  API Endpoints: #{total_api_endpoints}")
      IO.puts("  Potential Secrets: #{total_secrets}")
    end

    if failed > 0 do
      IO.puts("\nFailed URLs:")
      results
      |> Enum.filter(fn r -> Map.has_key?(r, :error) || r[:status] == :error end)
      |> Enum.each(fn r ->
        IO.puts("  #{r.url} - #{r[:error]}")
      end)
    end
  end
end
