
defmodule JSLurk.Analyzers.DOMSecurityScanner do
  @moduledoc """
  A module for scanning JavaScript files for DOM manipulation, HTML templates,
  DOM sinks, and comments that might indicate security vulnerabilities.
  """

  @doc """
  Scans text for DOM manipulation patterns and returns a map with categorized results.
  """
  def scan(text) when is_binary(text) do
    %{
      dom_manipulations: detect_dom_manipulations(text),
      html_templates: detect_html_templates(text),
      dom_sinks: detect_dom_sinks(text),
      comments: extract_comments(text)
    }
  end

  @doc """
  Detects DOM manipulation patterns in JavaScript code.
  """
  def detect_dom_manipulations(text) when is_binary(text) do
    patterns = [
      # Direct DOM manipulation
      {~r/document\.write\s*\(([^)]+)\)/i, "document.write"},
      {~r/\.innerHTML\s*=\s*([^;]+)/i, "innerHTML assignment"},
      {~r/\.outerHTML\s*=\s*([^;]+)/i, "outerHTML assignment"},
      {~r/\.insertAdjacentHTML\s*\(\s*(['"]).*?\1\s*,\s*([^)]+)\)/i, "insertAdjacentHTML"},
      
      # jQuery DOM manipulation
      {~r/\$\([^)]+\)\.html\s*\(([^)]+)\)/i, "jQuery html()"},
      {~r/\$\([^)]+\)\.append\s*\(([^)]+)\)/i, "jQuery append()"},
      {~r/\$\([^)]+\)\.prepend\s*\(([^)]+)\)/i, "jQuery prepend()"},
      {~r/\$\([^)]+\)\.after\s*\(([^)]+)\)/i, "jQuery after()"},
      {~r/\$\([^)]+\)\.before\s*\(([^)]+)\)/i, "jQuery before()"},
      
      # Modern DOM APIs
      {~r/\.insertBefore\s*\(([^,]+),\s*([^)]+)\)/i, "insertBefore"},
      {~r/\.appendChild\s*\(([^)]+)\)/i, "appendChild"},
      {~r/\.replaceChild\s*\(([^,]+),\s*([^)]+)\)/i, "replaceChild"},
      
      # Element creation
      {~r/document\.createElement\s*\(\s*(['"])div\1\s*\)/i, "createElement div"},
      {~r/document\.createElement\s*\(\s*(['"])iframe\1\s*\)/i, "createElement iframe"},
      {~r/document\.createElement\s*\(\s*(['"])script\1\s*\)/i, "createElement script"}
    ]
    
    Enum.flat_map(patterns, fn {pattern, type} ->
      Regex.scan(pattern, text)
      |> Enum.map(fn match ->
        code = List.first(match)
        %{
          type: type,
          code: code,
          line: find_line_number(text, code)
        }
      end)
    end)
  end

def detect_html_templates(text) when is_binary(text) do
    template_patterns = [
      # Template literals containing HTML
      {~r/`\s*<[a-z]+[^`]*>[^`]*<\/[a-z]+>\s*`/is, "Template literal HTML"},
      
      # HTML strings
      {~r/['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "HTML string"},
      
      # JSX/React components
      {~r/return\s*\(\s*<[A-Z][^>]*>[^<]*<\/[A-Z][^>]*>\s*\)/s, "JSX/React component"},
      
      # Vue templates
      {~r/template:\s*['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "Vue template"},
      
      # Angular templates
      {~r/templateUrl:\s*['"][^'"]+\.html['"]/i, "Angular templateUrl"},
      {~r/template:\s*['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "Angular inline template"}
    ]
    
    Enum.flat_map(template_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text, return: :index)
      |> Enum.map(fn [{start, length}] ->
        template_code = binary_part(text, start, length)
        %{
          type: type,
          code: template_code,
          line: find_line_number(text, template_code)
        }
      end)
    end)
  end

  @doc """
  Detects DOM sinks that could lead to XSS vulnerabilities.
  Focuses on security-relevant contexts for Function constructor usage.
  """
  def detect_dom_sinks(text) when is_binary(text) do
    # First, identify potential sources of user input or external data
    external_sources = identify_external_sources(text)
    
    # Basic sink patterns (non-Function constructor related)
    basic_sink_patterns = [
      # URL parameters
      {~r/location\.(?:search|hash|href)/i, "location object"},
      {~r/document\.URL/i, "document.URL"},
      {~r/document\.documentURI/i, "document.documentURI"},
      {~r/document\.referrer/i, "document.referrer"},
      
      # User input
      {~r/document\.getElementById\([^)]+\)\.value/i, "input value"},
      {~r/\$\(['"](#[^'"]+)['"]\)\.val\(\)/i, "jQuery val()"},
      
      # Local storage
      {~r/localStorage\.getItem\([^)]+\)/i, "localStorage.getItem"},
      {~r/sessionStorage\.getItem\([^)]+\)/i, "sessionStorage.getItem"},
      
      # Cookies
      {~r/document\.cookie/i, "document.cookie"},
      
      # Message events
      {~r/window\.addEventListener\(['"](message|postMessage)['"]/i, "message event"},
      
      # eval and similar (excluding Function constructor)
      {~r/eval\s*\(([^)]+)\)/i, "eval()"},
      {~r/setTimeout\s*\(\s*['"]([^'"]+)['"]/i, "setTimeout with string"},
      {~r/setInterval\s*\(\s*['"]([^'"]+)['"]/i, "setInterval with string"}
    ]
    
    # Process basic sink patterns
    basic_sinks = Enum.flat_map(basic_sink_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text)
      |> Enum.map(fn match ->
        code = List.first(match)
        %{
          type: type,
          code: code,
          line: find_line_number(text, code),
          risk: assess_risk(type)
        }
      end)
    end)
    
    # Now handle Function constructor specifically with context awareness
    function_constructor_sinks = detect_risky_function_constructors(text, external_sources)
    
    # Combine results
    basic_sinks ++ function_constructor_sinks
  end

  @doc """
  Extracts comments from JavaScript code.
  """
  def extract_comments(text) when is_binary(text) do
    comment_patterns = [
      # Single line comments
      {~r/\/\/(.*)$/, "Single-line comment"},
      
      # Multi-line comments
      {~r/\/\*(.*?)\*\//s, "Multi-line comment"},
      
      # HTML comments in template literals
      {~r/`[^`]*<!--(.*?)-->[^`]*`/s, "HTML comment in template literal"}
    ]
    
    Enum.flat_map(comment_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text, capture: :all_but_first)
      |> Enum.map(fn [content] ->
        trimmed_content = String.trim(content)
        %{
          type: type,
          content: trimmed_content,
          line: find_line_number(text, "//#{content}"),
          sensitive: contains_sensitive_info?(trimmed_content)
        }
      end)
    end)
  end

  @doc """
  Prints a summary of the scan results.
  """
  def print_summary(scan_results) do
    IO.puts("\n=== DOM Security Scan Results ===\n")
    
    IO.puts("DOM Manipulations (#{length(scan_results.dom_manipulations)}):")
    Enum.each(scan_results.dom_manipulations, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type}: #{truncate(item.code, 80)}")
    end)
    
    IO.puts("\nHTML Templates (#{length(scan_results.html_templates)}):")
    Enum.each(scan_results.html_templates, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type}: #{truncate(item.code, 80)}")
    end)
    
    IO.puts("\nDOM Sinks (#{length(scan_results.dom_sinks)}):")
    Enum.each(scan_results.dom_sinks, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type} (Risk: #{item.risk}): #{truncate(item.code, 80)}")
    end)
    
    sensitive_comments = Enum.filter(scan_results.comments, & &1.sensitive)
    IO.puts("\nPotentially Sensitive Comments (#{length(sensitive_comments)}/#{length(scan_results.comments)}):")
    Enum.each(sensitive_comments, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type}: #{truncate(item.content, 80)}")
    end)
    
    IO.puts("\n=== End of DOM Security Scan ===")
  end

  # Helper functions

  # Identifies potential sources of external data in the code
  defp identify_external_sources(text) do
    source_patterns = [
      ~r/(location\.(?:search|hash|href|pathname))/i,
      ~r/(document\.(?:URL|documentURI|referrer))/i,
      ~r/((?:local|session)Storage\.getItem\([^)]+\))/i,
      ~r/(document\.cookie)/i,
      ~r/(document\.getElementById\([^)]+\)\.value)/i,
      ~r/(\$\(['"](?:#[^'"]+)['"](?:\.val\(\)|\.text\(\)|\.html\(\)))/i,
      ~r/(new URLSearchParams\()/i,
      ~r/(fetch\([^)]+\))/i,
      ~r/(XMLHttpRequest)/i,
      ~r/(\.ajax\()/i
    ]
    
    Enum.flat_map(source_patterns, fn pattern ->
      Regex.scan(pattern, text, capture: :first)
      |> Enum.map(fn [source] -> source end)
    end)
  end

  # Detects risky Function constructor usage by looking for patterns where
  # external data might be passed to the constructor
  defp detect_risky_function_constructors(text, external_sources) do
    # First, find all Function constructor usages
    function_constructor_pattern = ~r/new\s+Function\s*\(([^)]*)\)/i
    
    Regex.scan(function_constructor_pattern, text, return: :index)
    |> Enum.map(fn indices ->
      # Extract the full constructor call using the first index pair
      # This handles cases where multiple capture groups are returned
      {start, length} = List.first(indices)
      
      constructor_code = binary_part(text, start, length)
      
      # Get the line number
      line = find_line_number(text, constructor_code)
      
      # Extract the arguments
      args_match = Regex.run(~r/new\s+Function\s*\(([^)]*)\)/i, constructor_code, capture: :all_but_first)
      args = if args_match, do: List.first(args_match), else: ""
      
      # Check if this usage is risky by looking for external sources in the arguments
      # or in the surrounding context (20 characters before and after)
      context_start = max(0, start - 20)
      context_length = min(String.length(text) - context_start, length + 40)
      context = binary_part(text, context_start, context_length)
      
      is_risky = risky_function_constructor?(args, context, external_sources)
      
      if is_risky do
        %{
          type: "Function constructor (risky)",
          code: constructor_code,
          line: line,
          risk: "High",
          context: context
        }
      else
        nil
      end
    end)
    |> Enum.reject(&is_nil/1)
  end

  # Determines if a Function constructor usage is risky based on its arguments and context
  defp risky_function_constructor?(args, context, external_sources) do
    # Check if any external source is directly used in the arguments
    direct_usage = Enum.any?(external_sources, fn source ->
      String.contains?(args, source)
    end)
    
    # Check for variable usage that might contain external data
    # This is a heuristic - we look for variables that are assigned external data
    # and then used in the Function constructor
    indirect_usage = Enum.any?(external_sources, fn source ->
      # Look for patterns like: var x = location.search; ... new Function(x)
      var_assignment = Regex.run(~r/(?:var|let|const)\s+(\w+)\s*=\s*#{Regex.escape(source)}/i, context)
      
      if var_assignment do
        var_name = Enum.at(var_assignment, 1)
        # Check if this variable is used in the Function constructor arguments
        String.contains?(args, var_name)
      else
        false
      end
    end)
    
    # Check for other risky patterns
    other_risky_patterns = [
      # JSON.parse of external data
      ~r/JSON\.parse\([^)]*(?:localStorage|sessionStorage|cookie|location|document\.URL)/i,
      # Decoding of URL components
      ~r/decodeURI(?:Component)?\([^)]*(?:location|document\.URL|search|hash)/i,
      # Passing user input directly
      ~r/getElementById\([^)]+\)\.value/i
    ]
    
    other_risks = Enum.any?(other_risky_patterns, fn pattern ->
      Regex.match?(pattern, context)
    end)
    
    # Also consider it risky if it appears in an event handler for messages
    in_message_handler = Regex.match?(~r/addEventListener\(['"](message|postMessage)['"][^{]*\{[^}]*new\s+Function/is, context)
    
    direct_usage || indirect_usage || other_risks || in_message_handler
  end

  defp find_line_number(text, substring) do
    case :binary.match(text, substring) do
      {pos, _} ->
        text_before = binary_part(text, 0, pos)
        String.split(text_before, "\n") |> length()
      :nomatch ->
        0
    end
  end

  defp assess_risk(type) do
    high_risk = ["eval()", "Function constructor (risky)", "setTimeout with string", 
                "setInterval with string", "document.write"]
    medium_risk = ["innerHTML assignment", "outerHTML assignment", "insertAdjacentHTML",
                  "location object", "document.URL", "document.cookie"]
    
    cond do
      Enum.member?(high_risk, type) -> "High"
      Enum.member?(medium_risk, type) -> "Medium"
      true -> "Low"
    end
  end

  defp contains_sensitive_info?(content) do
    sensitive_patterns = [
      ~r/password/i,
      ~r/api\s*key/i,
      ~r/secret/i,
      ~r/token/i,
      ~r/auth/i,
      ~r/credential/i,
      ~r/TODO/i,
      ~r/FIXME/i,
      ~r/HACK/i,
      ~r/XXX/i,
      ~r/BUG/i,
      ~r/SECURITY/i
    ]
    
    Enum.any?(sensitive_patterns, fn pattern ->
      Regex.match?(pattern, content)
    end)
  end

  defp truncate(text, max_length) do
    if String.length(text) > max_length do
      String.slice(text, 0, max_length) <> "..."
    else
      text
    end
  end
end
