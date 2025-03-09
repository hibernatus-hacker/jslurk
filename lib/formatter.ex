# lib/JSLurk/formatter.ex
defmodule JSLurk.Formatter do
  @moduledoc """
  Handles formatting and displaying scan results.
  """

  def print_summary(results) do
    IO.puts("\n=== JSLurk Scan Summary ===\n")
    
    total_urls = length(results)
    successful = Enum.count(results, &(is_integer(&1[:status]) && &1[:status] >= 200 && &1[:status] < 300))
    failed = total_urls - successful
    
    IO.puts("Scanned #{total_urls} URLs (#{successful} successful, #{failed} failed)")
    
    # Count totals
    total_json = Enum.reduce(results, 0, fn result, acc -> 
      acc + (result[:json_objects] || 0)
    end)
    
    total_api_endpoints = Enum.reduce(results, 0, fn result, acc -> 
      acc + (get_in(result, [:urls, :api_endpoints]) || 0)
    end)
    
    total_secrets = Enum.reduce(results, 0, fn result, acc -> 
      acc + (result[:secrets] || 0)
    end)
    
    total_dom_sinks = Enum.reduce(results, 0, fn result, acc -> 
      acc + (get_in(result, [:dom_security, :sinks]) || 0)
    end)
    
    IO.puts("Found:")
    IO.puts("  - #{total_json} JSON objects")
    IO.puts("  - #{total_api_endpoints} API endpoints")
    IO.puts("  - #{total_secrets} potential secrets")
    IO.puts("  - #{total_dom_sinks} DOM sinks (potential XSS)")
    
    # Print top findings
    if total_secrets > 0 do
      IO.puts("\n=== Top Secret Findings ===")
      
      results
      |> Enum.filter(&(&1[:secrets] && &1[:secrets] > 0))
      |> Enum.sort_by(&(&1[:secrets]), :desc)
      |> Enum.take(5)
      |> Enum.each(fn result ->
        IO.puts("  - #{result[:url]}: #{result[:secrets]} potential secrets")
      end)
    end
    
    if total_dom_sinks > 0 do
      IO.puts("\n=== Top DOM Security Issues ===")
      
      results
      |> Enum.filter(&(get_in(&1, [:dom_security, :sinks]) && get_in(&1, [:dom_security, :sinks]) > 0))
      |> Enum.sort_by(&(get_in(&1, [:dom_security, :sinks])), :desc)
      |> Enum.take(5)
      |> Enum.each(fn result ->
        IO.puts("  - #{result[:url]}: #{get_in(result, [:dom_security, :sinks])} DOM sinks")
      end)
    end
    
    IO.puts("\n=== End of Summary ===")
    
    # Return the results for potential further processing
    results
  end
end
