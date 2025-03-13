
defmodule JSLurk.Analyzers.DOMSecurityScanner do
  @moduledoc """
  A module for scanning JavaScript files for DOM manipulation, HTML templates,
  DOM sinks, and comments that might indicate security vulnerabilities.
  Optimized for bug bounty hunting and security analysis.
  """



  @doc """
  Scans text for DOM manipulation patterns and returns a map with categorized results.
  """
  def scan(text) when is_binary(text) do
    %{
      dom_manipulations: detect_dom_manipulations(text),
      html_templates: detect_html_templates(text),
      dom_sinks: detect_dom_sinks(text),
      comments: extract_comments(text),
      event_handlers: detect_event_handlers(text),
      postmessage_usage: detect_postmessage_usage(text)
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
      {~r/\.setHTML\s*\(([^)]+)\)/i, "setHTML"},

      # jQuery DOM manipulation
      {~r/\$\([^)]+\)\.html\s*\(([^)]+)\)/i, "jQuery html()"},
      {~r/\$\([^)]+\)\.append\s*\(([^)]+)\)/i, "jQuery append()"},
      {~r/\$\([^)]+\)\.prepend\s*\(([^)]+)\)/i, "jQuery prepend()"},
      {~r/\$\([^)]+\)\.after\s*\(([^)]+)\)/i, "jQuery after()"},
      {~r/\$\([^)]+\)\.before\s*\(([^)]+)\)/i, "jQuery before()"},
      {~r/\$\([^)]+\)\.replaceWith\s*\(([^)]+)\)/i, "jQuery replaceWith()"},
      {~r/\$\([^)]+\)\.wrapAll\s*\(([^)]+)\)/i, "jQuery wrapAll()"},

      # Modern DOM APIs
      {~r/\.insertBefore\s*\(([^,]+),\s*([^)]+)\)/i, "insertBefore"},
      {~r/\.appendChild\s*\(([^)]+)\)/i, "appendChild"},
      {~r/\.replaceChild\s*\(([^,]+),\s*([^)]+)\)/i, "replaceChild"},
      {~r/\.replaceWith\s*\(([^)]+)\)/i, "replaceWith"},
      {~r/\.insertNode\s*\(([^)]+)\)/i, "insertNode"},
      {~r/\.after\s*\(([^)]+)\)/i, "after"},
      {~r/\.before\s*\(([^)]+)\)/i, "before"},

      # Element creation
      {~r/document\.createElement\s*\(\s*(['"])div\1\s*\)/i, "createElement div"},
      {~r/document\.createElement\s*\(\s*(['"])iframe\1\s*\)/i, "createElement iframe"},
      {~r/document\.createElement\s*\(\s*(['"])script\1\s*\)/i, "createElement script"},
      {~r/document\.createElement\s*\(\s*(['"])a\1\s*\)/i, "createElement anchor"},
      {~r/document\.createElement\s*\(\s*(['"])object\1\s*\)/i, "createElement object"},
      {~r/document\.createElement\s*\(\s*(['"])embed\1\s*\)/i, "createElement embed"},

      # Framework-specific
      {~r/dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*([^}]+)\}/i, "React dangerouslySetInnerHTML"},
      {~r/v-html\s*=\s*["']([^"']+)["']/i, "Vue v-html directive"},
      {~r/\[innerHTML\]\s*=\s*["']([^"']+)["']/i, "Angular [innerHTML]"}
    ]

    Enum.flat_map(patterns, fn {pattern, type} ->
      Regex.scan(pattern, text)
      |> Enum.map(fn match ->
        code = List.first(match)
        %{
          type: type,
          code: code,
          line: find_line_number(text, code),
          risk: assess_dom_manipulation_risk(type, code)
        }
      end)
    end)
  end

  @doc """
  Detects HTML templates in JavaScript code.
  """
  def detect_html_templates(text) when is_binary(text) do
    template_patterns = [
      # Template literals containing HTML
      {~r/`\s*<[a-z]+[^`]*>[^`]*<\/[a-z]+>\s*`/is, "Template literal HTML"},

      # HTML strings
      {~r/['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "HTML string"},

      # JSX/React components
      {~r/return\s*\(\s*<[A-Z][^>]*>[^<]*<\/[A-Z][^>]*>\s*\)/s, "JSX/React component"},
      {~r/<[A-Z][a-zA-Z0-9]*\s+[^>]*>/s, "JSX component tag"},

      # Vue templates
      {~r/template:\s*['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "Vue template"},
      {~r/<template>[\s\S]*?<\/template>/i, "Vue SFC template"},

      # Angular templates
      {~r/templateUrl:\s*['"][^'"]+\.html['"]/i, "Angular templateUrl"},
      {~r/template:\s*['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "Angular inline template"},

      # HTML in strings with concatenation
      {~r/['"]<[a-z]+[^'"]*>['"][\s+]*\+[\s+]*[^+;]+\+[\s+]*['"][^'"]*<\/[a-z]+>['"]/is, "Concatenated HTML string"}
    ]

    Enum.flat_map(template_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text, return: :index)
      |> Enum.map(fn [{start, length}] ->
        template_code = binary_part(text, start, length)
        %{
          type: type,
          code: template_code,
          line: find_line_number(text, template_code),
          contains_variables: contains_variables?(template_code)
        }
      end)
    end)
  end

  @doc """
  Detects DOM sinks that could lead to XSS vulnerabilities.
  Significantly expanded to cover more sinks and contexts.
  """
  def detect_dom_sinks(text) when is_binary(text) do
    # First, identify potential sources of user input or external data
    external_sources = identify_external_sources(text)

    # Basic sink patterns (expanded)
    basic_sink_patterns = [
      # URL parameters
      {~r/location\.(?:search|hash|href|pathname)/i, "location object"},
      {~r/document\.URL/i, "document.URL"},
      {~r/document\.documentURI/i, "document.documentURI"},
      {~r/document\.referrer/i, "document.referrer"},
      {~r/window\.name/i, "window.name"},

      # URL parsing
      {~r/new URL\(([^)]+)\)/i, "URL constructor"},
      {~r/new URLSearchParams\(([^)]+)\)/i, "URLSearchParams"},
      {~r/URLSearchParams\.get\(([^)]+)\)/i, "URLSearchParams.get"},

      # User input
      {~r/document\.getElementById\([^)]+\)\.value/i, "input value"},
      {~r/document\.querySelector\([^)]+\)\.value/i, "querySelector value"},
      {~r/\$\(['"](#[^'"]+)['"]\)\.val\(\)/i, "jQuery val()"},
      {~r/\$\([^)]+\)\.text\(\)/i, "jQuery text()"},
      {~r/\$\([^)]+\)\.html\(\)/i, "jQuery html()"},

      # Storage
      {~r/localStorage\.getItem\([^)]+\)/i, "localStorage.getItem"},
      {~r/localStorage\[[^\]]+\]/i, "localStorage[] access"},
      {~r/sessionStorage\.getItem\([^)]+\)/i, "sessionStorage.getItem"},
      {~r/sessionStorage\[[^\]]+\]/i, "sessionStorage[] access"},

      # Cookies
      {~r/document\.cookie/i, "document.cookie"},
      {~r/Cookies\.get\([^)]+\)/i, "Cookies.get"},
      {~r/getCookie\([^)]+\)/i, "getCookie function"},

      # Message events
      {~r/window\.addEventListener\(['"](message|postMessage)['"]/i, "message event"},
      {~r/onmessage\s*=/i, "onmessage handler"},

      # eval and similar - REMOVED Function constructor patterns
      {~r/eval\s*\(([^)]+)\)/i, "eval()"},
      {~r/setTimeout\s*\(\s*['"]([^'"]+)['"]/i, "setTimeout with string"},
      {~r/setInterval\s*\(\s*['"]([^'"]+)['"]/i, "setInterval with string"},

      # Document domain
      {~r/document\.domain\s*=/i, "document.domain assignment"},

      # Script injection
      {~r/\.src\s*=\s*([^;]+)/i, "script.src assignment"},
      {~r/document\.write\s*\(([^)]+)\)/i, "document.write"},
      {~r/document\.writeln\s*\(([^)]+)\)/i, "document.writeln"},

      # iframe injection
      {~r/iframe\.src\s*=\s*([^;]+)/i, "iframe.src assignment"},
      {~r/iframe\.contentWindow/i, "iframe.contentWindow access"},
      {~r/iframe\.contentDocument/i, "iframe.contentDocument access"},

      # Dynamic imports
      {~r/import\s*\(([^)]+)\)/i, "dynamic import()"},
      {~r/require\s*\(([^)]+)\)/i, "require()"},

      # Web Workers
      {~r/new Worker\s*\(([^)]+)\)/i, "Web Worker constructor"},

      # Dangerous attributes
      {~r/\.setAttribute\s*\(\s*['"](?:href|src|action|formaction|data|onclick|onerror)['"]\s*,\s*([^)]+)\)/i, "setAttribute (dangerous)"},

      # JSON parsing
      {~r/JSON\.parse\s*\(([^)]+)\)/i, "JSON.parse"},

      # URL redirection
      {~r/location\s*=\s*([^;]+)/i, "location assignment"},
      {~r/location\.(?:assign|replace|href)\s*\(\s*([^)]+)\)/i, "location method"},
      {~r/window\.open\s*\(\s*([^,)]+)/i, "window.open"},
      {~r/\.(?:href|src|action)\s*=\s*([^;]+)/i, "href/src/action assignment"},

      # Fetch API
      {~r/fetch\s*\(\s*([^,)]+)/i, "fetch API"},

      # XMLHttpRequest
      {~r/\.open\s*\(\s*['"][A-Z]+['"],\s*([^,)]+)/i, "XMLHttpRequest.open"},

      # jQuery AJAX
      {~r/\$\.(?:get|post|ajax)\s*\(\s*([^,)]+)/i, "jQuery AJAX"},

      # Clipboard API
      {~r/navigator\.clipboard\.writeText\s*\(\s*([^)]+)\)/i, "clipboard.writeText"},

      # Blob URLs
      {~r/URL\.createObjectURL\s*\(\s*([^)]+)\)/i, "createObjectURL"},

      # Service Workers
      {~r/navigator\.serviceWorker\.register\s*\(\s*([^,)]+)/i, "serviceWorker.register"}
    ]

    # Process basic sink patterns
    basic_sinks = Enum.flat_map(basic_sink_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text)
      |> Enum.map(fn match ->
        code = List.first(match)

        # Determine if this sink is connected to an external source
        connected_to_source = sink_connected_to_source?(code, text, external_sources)

        %{
          type: type,
          code: code,
          line: find_line_number(text, code),
          risk: assess_risk(type, connected_to_source),
          connected_to_source: connected_to_source
        }
      end)
    end)

    # Detect DOM-based XSS sinks with data flow analysis
    dom_xss_sinks = detect_dom_xss_sinks(text, external_sources)

    # Combine results
    basic_sinks ++ dom_xss_sinks
  end

  @doc """
  Detects event handlers that might be security-relevant.
  """
  def detect_event_handlers(text) when is_binary(text) do
    event_handler_patterns = [
      # addEventListener
      {~r/\.addEventListener\s*\(\s*['"]([^'"]+)['"]/i, "addEventListener"},

      # Inline event handlers
      {~r/\.on([a-z]+)\s*=\s*function/i, "on* property"},
      {~r/\.on([a-z]+)\s*=\s*\(/i, "on* arrow function"},

      # jQuery event handlers
      {~r/\$\([^)]+\)\.on\s*\(\s*['"]([^'"]+)['"]/i, "jQuery on()"},
      {~r/\$\([^)]+\)\.bind\s*\(\s*['"]([^'"]+)['"]/i, "jQuery bind()"},

      # React event handlers
      {~r/on[A-Z][a-zA-Z]+\s*=\s*\{([^}]+)\}/i, "React event handler"},

      # Security-relevant event types
      {~r/\.addEventListener\s*\(\s*['"]message['"]/i, "message event listener"},
      {~r/\.addEventListener\s*\(\s*['"]storage['"]/i, "storage event listener"},
      {~r/\.addEventListener\s*\(\s*['"]popstate['"]/i, "popstate event listener"},
      {~r/\.onmessage\s*=/i, "onmessage handler"},
      {~r/\.onstorage\s*=/i, "onstorage handler"},
      {~r/\.onpopstate\s*=/i, "onpopstate handler"}
    ]

    Enum.flat_map(event_handler_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text)
      |> Enum.map(fn match ->
        code = List.first(match)
        event_type = case match do
          [_, event_type | _] -> event_type
          _ -> "unknown"
        end

        %{
          type: type,
          event_type: event_type,
          code: code,
          line: find_line_number(text, code),
          security_relevant: security_relevant_event?(event_type)
        }
      end)
    end)
  end

  @doc """
  Detects postMessage usage which can lead to security issues.
  """
  def detect_postmessage_usage(text) when is_binary(text) do
    postmessage_patterns = [
      # Sending messages
      {~r/(postMessage\s*\([^,)]*,[^)]*\))/i, "postMessage sending"},
      {~r/(\.contentWindow\.postMessage\s*\([^,)]*,[^)]*\))/i, "iframe postMessage"},
      {~r/(window\.opener\.postMessage\s*\([^,)]*,[^)]*\))/i, "opener postMessage"},
      {~r/(window\.parent\.postMessage\s*\([^,)]*,[^)]*\))/i, "parent postMessage"},

      # Receiving messages
      {~r/(addEventListener\s*\(\s*['"]message['"]\s*,\s*[^,)]+)/i, "message event listener"},
      {~r/(onmessage\s*=\s*[^;]+)/i, "onmessage handler"}
    ]

    Enum.flat_map(postmessage_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text, capture: :all_but_first)
      |> Enum.map(fn [code] ->
        # Check for origin validation
        has_origin_check = if String.contains?(type, "message event") do
          # Look for origin checks in the handler
          origin_check_context = extract_context(text, code, 200)
          Regex.match?(~r/(?:event|e|msg|message)\.origin(?:\s*===?\s*['"][^'"]+['"]|\s*!==?\s*['"][^'"]+['"]|\.(?:includes|indexOf|startsWith|endsWith))/i, origin_check_context)
        else
          # For sending, check if the third parameter (targetOrigin) is "*"
          if String.contains?(type, "postMessage sending") do
            !Regex.match?(~r/postMessage\s*\([^,]*,\s*[^,]*,\s*['"]?\*['"]?\)/i, code)
          else
            false
          end
        end

        %{
          type: type,
          code: code,
          line: find_line_number(text, code),
          has_origin_check: has_origin_check,
          risk: if(has_origin_check, do: "Low", else: "High")
        }
      end)
    end)
  end

  @doc """
  Extracts comments from JavaScript code.
  """
  def extract_comments(text) when is_binary(text) do
    comment_patterns = [
      # Single line comments
      {~r/\/\/(.*)$/m, "Single-line comment"},

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
          line: find_line_number(text, if(type == "Single-line comment", do: "//#{content}", else: "/*#{content}*/")),
          sensitive: contains_sensitive_info?(trimmed_content)
        }
      end)
    end)
  end

  @doc """
  Prints a summary of the scan results without truncating any output.
  Only includes Medium and High risk findings.
  """
  def print_summary(scan_results) do
    IO.puts("\n=== DOM Security Scan Results ===\n")

    # Filter DOM Manipulations to only include Medium and High risk
    high_medium_dom_manipulations = Enum.filter(scan_results.dom_manipulations, fn item ->
      Map.get(item, :risk, "Low") in ["Medium", "High"]
    end)

    IO.puts("DOM Manipulations (#{length(high_medium_dom_manipulations)}):")
    Enum.each(high_medium_dom_manipulations, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type}: #{item.code}")
    end)

    # Filter HTML Templates to only include those with variables (higher risk)
    risky_templates = Enum.filter(scan_results.html_templates, fn item ->
      Map.get(item, :contains_variables, false) == true
    end)

    IO.puts("\nHTML Templates with Variables (#{length(risky_templates)}):")
    Enum.each(risky_templates, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type}: #{item.code}")
    end)

    # Filter DOM Sinks to only include Medium and High risk
    high_medium_dom_sinks = Enum.filter(scan_results.dom_sinks, fn item ->
      Map.get(item, :risk, "Low") in ["Medium", "High"]
    end)

    IO.puts("\nDOM Sinks (#{length(high_medium_dom_sinks)}):")
    Enum.each(high_medium_dom_sinks, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type} (Risk: #{item.risk}): #{item.code}")
    end)

    # Filter Event Handlers to only include security-relevant ones
    security_relevant_handlers = Enum.filter(scan_results.event_handlers, fn item ->
      Map.get(item, :security_relevant, false) == true
    end)

    IO.puts("\nSecurity-Relevant Event Handlers (#{length(security_relevant_handlers)}):")
    Enum.each(security_relevant_handlers, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type} (#{item.event_type}): #{item.code}")
    end)

    # Filter PostMessage Usage to only include high risk (no origin check)
    risky_postmessage = Enum.filter(scan_results.postmessage_usage, fn item ->
      Map.get(item, :risk, "Low") == "High"
    end)

    IO.puts("\nRisky PostMessage Usage (#{length(risky_postmessage)}):")
    Enum.each(risky_postmessage, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type} (Origin Check: No): #{item.code}")
    end)

    # Keep all sensitive comments as they're important
    sensitive_comments = Enum.filter(scan_results.comments, & &1.sensitive)
    IO.puts("\nPotentially Sensitive Comments (#{length(sensitive_comments)}/#{length(scan_results.comments)}):")
    Enum.each(sensitive_comments, fn item ->
      IO.puts("  - [Line #{item.line}] #{item.type}: #{item.content}")
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
      ~r/((?:local|session)Storage\[[^\]]+\])/i,
      ~r/(document\.cookie)/i,
      ~r/(document\.getElementById\([^)]+\)\.value)/i,
      ~r/(document\.querySelector\([^)]+\)\.value)/i,
      ~r/(\$\(['"](?:#[^'"]+)['"](?:\.val\(\)|\.text\(\)|\.html\(\)))/i,
      ~r/(new URLSearchParams\()/i,
      ~r/(URLSearchParams\.get\([^)]+\))/i,
      ~r/(window\.name)/i,
      ~r/(fetch\([^)]+\))/i,
      ~r/(XMLHttpRequest)/i,
      ~r/(\.ajax\()/i,
      ~r/(\.open\s*\(\s*['"][A-Z]+['"],\s*[^,)]+)/i,
      ~r/(window\.addEventListener\(['"]message['"])/i,
      ~r/(onmessage\s*=)/i
    ]

    Enum.flat_map(source_patterns, fn pattern ->
      Regex.scan(pattern, text, capture: :first)
      |> Enum.map(fn [source] -> source end)
    end)
  end

  # Detects DOM-based XSS sinks with data flow analysis
  defp detect_dom_xss_sinks(text, external_sources) do
    # DOM XSS sink patterns
    dom_xss_patterns = [
      {~r/(\.innerHTML\s*=\s*[^;]+)/i, "innerHTML assignment"},
      {~r/(\.outerHTML\s*=\s*[^;]+)/i, "outerHTML assignment"},
      {~r/(\.insertAdjacentHTML\s*\([^)]+\))/i, "insertAdjacentHTML"},
      {~r/(document\.write\s*\([^)]+\))/i, "document.write"},
      {~r/(document\.writeln\s*\([^)]+\))/i, "document.writeln"},
      {~r/(\$\([^)]+\)\.html\s*\([^)]+\))/i, "jQuery html()"},
      {~r/(dangerouslySetInnerHTML\s*=\s*\{\s*__html\s*:\s*[^}]+\})/i, "React dangerouslySetInnerHTML"},
      {~r/(v-html\s*=\s*["'][^"']+["'])/i, "Vue v-html directive"}
    ]

    Enum.flat_map(dom_xss_patterns, fn {pattern, type} ->
      Regex.scan(pattern, text, capture: :all_but_first)
      |> Enum.map(fn [code] ->
        # Get context around the sink
        context = extract_context(text, code, 200)

        # Check if any external source flows into this sink
        source_flows_to_sink = source_flows_to_sink?(code, context, external_sources)

        # Determine risk level based on source flow
        risk = if source_flows_to_sink, do: "High", else: "Medium"

        %{
          type: "DOM XSS Sink: #{type}",
          code: code,
          line: find_line_number(text, code),
          risk: risk,
          source_flows_to_sink: source_flows_to_sink,
          context: context
        }
      end)
    end)
  end

  # Determines if a Function constructor usage is risky based on its arguments and context
  defp risky_function_constructor?(args, context, external_sources) do
    # Check if any external source is directly used in the arguments
    direct_usage = Enum.any?(external_sources, fn source ->
      String.contains?(args, source)
    end)

    # Check for variable usage that might contain external data
    indirect_usage = Enum.any?(external_sources, fn source ->
      # Look for patterns like: var x = location.search; ... new Function(x)
      var_assignment = Regex.run(~r/(?:var|let|const)\s+(\w+)\s*=\s*(?:[^;]*#{Regex.escape(source)}[^;]*)/i, context)

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
      ~r/getElementById\([^)]+\)\.value/i,
      # Passing data from fetch/ajax responses
      ~r/\.then\s*\(\s*(?:function\s*\([^)]*\)|[^=>\s]+\s*=>)/i
    ]

    other_risks = Enum.any?(other_risky_patterns, fn pattern ->
      Regex.match?(pattern, context)
    end)

    # Also consider it risky if it appears in an event handler for messages
    in_message_handler = Regex.match?(~r/addEventListener\(['"](message|postMessage)['"][^{]*\{[^}]*(?:new\s+Function|Function)/is, context)

    direct_usage || indirect_usage || other_risks || in_message_handler
  end

  # Determines if a source flows to a sink
  defp source_flows_to_sink?(sink_code, context, external_sources) do
    # Extract variable names that might be used in the sink
    sink_vars = extract_variables_from_code(sink_code)

    # Check if any external source directly flows into the sink
    # Check if any external source directly flows into the sink
    direct_flow = Enum.any?(external_sources, fn source ->
      String.contains?(sink_code, source)
    end)

    # Check for indirect flow through variables
    indirect_flow = Enum.any?(sink_vars, fn var ->
      # Look for variable assignments that include external sources
      Enum.any?(external_sources, fn source ->
        # Pattern: var x = ...source...
        var_assignment = Regex.run(~r/(?:var|let|const)\s+#{Regex.escape(var)}\s*=\s*([^;]+)/i, context)

        if var_assignment do
          assignment_value = Enum.at(var_assignment, 1)
          String.contains?(assignment_value, source)
        else
          # Check for other assignment patterns: x = ...source...
          other_assignment = Regex.run(~r/#{Regex.escape(var)}\s*=\s*([^;]+)/i, context)

          if other_assignment do
            assignment_value = Enum.at(other_assignment, 1)
            String.contains?(assignment_value, source)
          else
            false
          end
        end
      end)
    end)

    # Check for flow through function parameters
    function_flow = Regex.match?(~r/function\s+\w+\s*\([^)]*\)\s*\{[^}]*#{Regex.escape(sink_code)}/i, context) &&
                    Enum.any?(external_sources, fn source ->
                      Regex.match?(~r/\w+\s*\(\s*[^)]*#{Regex.escape(source)}[^)]*\)/i, context)
                    end)

    direct_flow || indirect_flow || function_flow
  end

  # Extracts variable names that might be used in code
  defp extract_variables_from_code(code) do
    # This is a simplified approach - a real implementation would need a proper parser
    # Look for identifiers that might be variables
    Regex.scan(~r/\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b/i, code)
    |> Enum.map(fn [_, var] -> var end)
    |> Enum.uniq()
    |> Enum.reject(fn var ->
      # Filter out common keywords and built-ins
      Enum.member?(["var", "let", "const", "function", "if", "else", "for", "while",
                   "return", "true", "false", "null", "undefined", "document",
                   "window", "console", "this", "new"], var)
    end)
  end

  # Extracts context around a piece of code
  defp extract_context(text, code, context_size) do
    case :binary.match(text, code) do
      {pos, len} ->
        start_pos = max(0, pos - context_size)
        end_pos = min(String.length(text), pos + len + context_size)
        binary_part(text, start_pos, end_pos - start_pos)
      :nomatch ->
        ""
    end
  end

  # Determines if a sink is connected to an external source
  defp sink_connected_to_source?(sink_code, text, external_sources) do
    # Get context around the sink
    context = extract_context(text, sink_code, 200)

    # Check if any external source directly flows into the sink
    direct_flow = Enum.any?(external_sources, fn source ->
      String.contains?(sink_code, source)
    end)

    # Check for variable assignments that might connect sources to sinks
    if direct_flow do
      true
    else
      # Extract variable names from the sink code
      sink_vars = extract_variables_from_code(sink_code)

      # Check if any of these variables are assigned values from external sources
      Enum.any?(sink_vars, fn var ->
        # Look for assignments like: var x = ...source...
        Enum.any?(external_sources, fn source ->
          assignment_pattern = ~r/(?:var|let|const)?\s*#{Regex.escape(var)}\s*=\s*([^;]+)/i

          case Regex.run(assignment_pattern, context) do
            [_, assignment] -> String.contains?(assignment, source)
            _ -> false
          end
        end)
      end)
    end
  end

  # Determines if an event type is security-relevant
  defp security_relevant_event?(event_type) do
    security_relevant_events = [
      "message", "postmessage", "storage", "popstate", "hashchange",
      "beforeunload", "unload", "pagehide", "pageshow", "visibilitychange",
      "load", "DOMContentLoaded", "readystatechange"
    ]

    String.downcase(event_type) in security_relevant_events
  end

  # Finds the line number of a substring in text
  defp find_line_number(text, substring) do
    case :binary.match(text, substring) do
      {pos, _} ->
        text_before = binary_part(text, 0, pos)
        String.split(text_before, "\n") |> length()
      :nomatch ->
        0
    end
  end

  # Assesses risk level based on sink type and connection to sources
  defp assess_risk(type, connected_to_source) do
    high_risk = ["eval()", "Function constructor", "setTimeout with string",
                "setInterval with string", "document.write", "document.writeln"]
    medium_risk = ["innerHTML assignment", "outerHTML assignment", "insertAdjacentHTML",
                  "location object", "document.URL", "document.cookie"]

    base_risk = cond do
      Enum.member?(high_risk, type) -> "High"
      Enum.member?(medium_risk, type) -> "Medium"
      true -> "Low"
    end

    # Increase risk if connected to an external source
    if connected_to_source do
      case base_risk do
        "Low" -> "Medium"
        "Medium" -> "High"
        "High" -> "High"
      end
    else
      base_risk
    end
  end

  # Assesses risk level for DOM manipulation based on type and code
  defp assess_dom_manipulation_risk(type, code) do
    high_risk_types = ["document.write", "innerHTML assignment", "outerHTML assignment",
                      "insertAdjacentHTML", "jQuery html()", "React dangerouslySetInnerHTML",
                      "Vue v-html directive"]

    medium_risk_types = ["jQuery append()", "jQuery prepend()", "createElement script",
                        "createElement iframe"]

    base_risk = cond do
      Enum.member?(high_risk_types, type) -> "High"
      Enum.member?(medium_risk_types, type) -> "Medium"
      true -> "Low"
    end

    # Increase risk if the code contains dynamic content (variables, template literals, etc.)
    if contains_dynamic_content?(code) do
      case base_risk do
        "Low" -> "Medium"
        "Medium" -> "High"
        "High" -> "High"
      end
    else
      base_risk
    end
  end

  # Checks if code contains dynamic content (variables, expressions, etc.)
  defp contains_dynamic_content?(code) do
    # Check for template literals with expressions
    template_literal = Regex.match?(~r/`[^`]*\${[^`]*}`/, code)

    # Check for string concatenation
    concatenation = Regex.match?(~r/['"][^'"]*['"][\s+]*\+/, code)

    # Check for variables
    variables = Regex.match?(~r/\$\{[^}]+\}|\$\([^)]+\)|\$[a-zA-Z0-9_]+/, code) or
                Regex.match?(~r/\b[a-zA-Z_$][a-zA-Z0-9_$]*\b/, code)

    template_literal || concatenation || variables
  end

  # Checks if a template contains variables or expressions
  defp contains_variables?(template) do
    # Check for template literal expressions
    template_expressions = Regex.match?(~r/\${[^}]+}/, template)

    # Check for Vue/Angular bindings
    framework_bindings = Regex.match?(~r/{{[^}]+}}|v-bind:|:[\w-]+|ng-bind|ng-model|\[\w+\]/, template)

    # Check for React JSX expressions
    jsx_expressions = Regex.match?(~r/{[^}]+}/, template)

    template_expressions || framework_bindings || jsx_expressions
  end

  # Checks if a comment contains sensitive information
  defp contains_sensitive_info?(content) do
    sensitive_patterns = [
      # Credentials and secrets
      ~r/password/i,
      ~r/passwd/i,
      ~r/api\s*key/i,
      ~r/secret/i,
      ~r/token/i,
      ~r/auth/i,
      ~r/credential/i,
      ~r/private/i,

      # Developer comments
      ~r/TODO/i,
      ~r/FIXME/i,
      ~r/HACK/i,
      ~r/XXX/i,
      ~r/BUG/i,
      ~r/SECURITY/i,
      ~r/VULNERABILITY/i,
      ~r/SENSITIVE/i,
      ~r/UNSAFE/i,

      # Debugging info
      ~r/DEBUG/i,
      ~r/console\.log/i,
      ~r/alert\(/i,

      # Temporary code
      ~r/TEMPORARY/i,
      ~r/TEMP/i,
      ~r/REMOVE/i,
      ~r/BEFORE PROD/i,
      ~r/BEFORE PRODUCTION/i,

      # Internal information
      ~r/internal/i,
      ~r/not for public/i,
      ~r/backend/i,
      ~r/localhost/i,
      ~r/127\.0\.0\.1/i,
      ~r/staging/i,
      ~r/test environment/i
    ]

    Enum.any?(sensitive_patterns, fn pattern ->
      Regex.match?(pattern, content)
    end)
  end
end





# defmodule JSLurk.Analyzers.DOMSecurityScanner do
#   @moduledoc """
#   A module for scanning JavaScript files for DOM manipulation, HTML templates,
#   DOM sinks, and comments that might indicate security vulnerabilities.
#   """
#
#   @doc """
#   Scans text for DOM manipulation patterns and returns a map with categorized results.
#   """
#   def scan(text) when is_binary(text) do
#     %{
#       dom_manipulations: detect_dom_manipulations(text),
#       html_templates: detect_html_templates(text),
#       dom_sinks: detect_dom_sinks(text),
#       comments: extract_comments(text)
#     }
#   end
#
#   @doc """
#   Detects DOM manipulation patterns in JavaScript code.
#   """
#   def detect_dom_manipulations(text) when is_binary(text) do
#     patterns = [
#       # Direct DOM manipulation
#       {~r/document\.write\s*\(([^)]+)\)/i, "document.write"},
#       {~r/\.innerHTML\s*=\s*([^;]+)/i, "innerHTML assignment"},
#       {~r/\.outerHTML\s*=\s*([^;]+)/i, "outerHTML assignment"},
#       {~r/\.insertAdjacentHTML\s*\(\s*(['"]).*?\1\s*,\s*([^)]+)\)/i, "insertAdjacentHTML"},
#
#       # jQuery DOM manipulation
#       {~r/\$\([^)]+\)\.html\s*\(([^)]+)\)/i, "jQuery html()"},
#       {~r/\$\([^)]+\)\.append\s*\(([^)]+)\)/i, "jQuery append()"},
#       {~r/\$\([^)]+\)\.prepend\s*\(([^)]+)\)/i, "jQuery prepend()"},
#       {~r/\$\([^)]+\)\.after\s*\(([^)]+)\)/i, "jQuery after()"},
#       {~r/\$\([^)]+\)\.before\s*\(([^)]+)\)/i, "jQuery before()"},
#
#       # Modern DOM APIs
#       {~r/\.insertBefore\s*\(([^,]+),\s*([^)]+)\)/i, "insertBefore"},
#       {~r/\.appendChild\s*\(([^)]+)\)/i, "appendChild"},
#       {~r/\.replaceChild\s*\(([^,]+),\s*([^)]+)\)/i, "replaceChild"},
#
#       # Element creation
#       {~r/document\.createElement\s*\(\s*(['"])div\1\s*\)/i, "createElement div"},
#       {~r/document\.createElement\s*\(\s*(['"])iframe\1\s*\)/i, "createElement iframe"},
#       {~r/document\.createElement\s*\(\s*(['"])script\1\s*\)/i, "createElement script"}
#     ]
#
#     Enum.flat_map(patterns, fn {pattern, type} ->
#       Regex.scan(pattern, text)
#       |> Enum.map(fn match ->
#         code = List.first(match)
#         %{
#           type: type,
#           code: code,
#           line: find_line_number(text, code)
#         }
#       end)
#     end)
#   end
#
# def detect_html_templates(text) when is_binary(text) do
#     template_patterns = [
#       # Template literals containing HTML
#       {~r/`\s*<[a-z]+[^`]*>[^`]*<\/[a-z]+>\s*`/is, "Template literal HTML"},
#
#       # HTML strings
#       {~r/['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "HTML string"},
#
#       # JSX/React components
#       {~r/return\s*\(\s*<[A-Z][^>]*>[^<]*<\/[A-Z][^>]*>\s*\)/s, "JSX/React component"},
#
#       # Vue templates
#       {~r/template:\s*['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "Vue template"},
#
#       # Angular templates
#       {~r/templateUrl:\s*['"][^'"]+\.html['"]/i, "Angular templateUrl"},
#       {~r/template:\s*['"]<[a-z]+[^'"]*>[^'"]*<\/[a-z]+>['"]/is, "Angular inline template"}
#     ]
#
#     Enum.flat_map(template_patterns, fn {pattern, type} ->
#       Regex.scan(pattern, text, return: :index)
#       |> Enum.map(fn [{start, length}] ->
#         template_code = binary_part(text, start, length)
#         %{
#           type: type,
#           code: template_code,
#           line: find_line_number(text, template_code)
#         }
#       end)
#     end)
#   end
#
#   @doc """
#   Detects DOM sinks that could lead to XSS vulnerabilities.
#   Focuses on security-relevant contexts for Function constructor usage.
#   """
#   def detect_dom_sinks(text) when is_binary(text) do
#     # First, identify potential sources of user input or external data
#     external_sources = identify_external_sources(text)
#
#     # Basic sink patterns (non-Function constructor related)
#     basic_sink_patterns = [
#       # URL parameters
#       {~r/location\.(?:search|hash|href)/i, "location object"},
#       {~r/document\.URL/i, "document.URL"},
#       {~r/document\.documentURI/i, "document.documentURI"},
#       {~r/document\.referrer/i, "document.referrer"},
#
#       # User input
#       {~r/document\.getElementById\([^)]+\)\.value/i, "input value"},
#       {~r/\$\(['"](#[^'"]+)['"]\)\.val\(\)/i, "jQuery val()"},
#
#       # Local storage
#       {~r/localStorage\.getItem\([^)]+\)/i, "localStorage.getItem"},
#       {~r/sessionStorage\.getItem\([^)]+\)/i, "sessionStorage.getItem"},
#
#       # Cookies
#       {~r/document\.cookie/i, "document.cookie"},
#
#       # Message events
#       {~r/window\.addEventListener\(['"](message|postMessage)['"]/i, "message event"},
#
#       # eval and similar (excluding Function constructor)
#       {~r/eval\s*\(([^)]+)\)/i, "eval()"},
#       {~r/setTimeout\s*\(\s*['"]([^'"]+)['"]/i, "setTimeout with string"},
#       {~r/setInterval\s*\(\s*['"]([^'"]+)['"]/i, "setInterval with string"}
#     ]
#
#     # Process basic sink patterns
#     basic_sinks = Enum.flat_map(basic_sink_patterns, fn {pattern, type} ->
#       Regex.scan(pattern, text)
#       |> Enum.map(fn match ->
#         code = List.first(match)
#         %{
#           type: type,
#           code: code,
#           line: find_line_number(text, code),
#           risk: assess_risk(type)
#         }
#       end)
#     end)
#
#     # Now handle Function constructor specifically with context awareness
#     function_constructor_sinks = detect_risky_function_constructors(text, external_sources)
#
#     # Combine results
#     basic_sinks ++ function_constructor_sinks
#   end
#
#   @doc """
#   Extracts comments from JavaScript code.
#   """
#   def extract_comments(text) when is_binary(text) do
#     comment_patterns = [
#       # Single line comments
#       {~r/\/\/(.*)$/, "Single-line comment"},
#
#       # Multi-line comments
#       {~r/\/\*(.*?)\*\//s, "Multi-line comment"},
#
#       # HTML comments in template literals
#       {~r/`[^`]*<!--(.*?)-->[^`]*`/s, "HTML comment in template literal"}
#     ]
#
#     Enum.flat_map(comment_patterns, fn {pattern, type} ->
#       Regex.scan(pattern, text, capture: :all_but_first)
#       |> Enum.map(fn [content] ->
#         trimmed_content = String.trim(content)
#         %{
#           type: type,
#           content: trimmed_content,
#           line: find_line_number(text, "//#{content}"),
#           sensitive: contains_sensitive_info?(trimmed_content)
#         }
#       end)
#     end)
#   end
#
#   @doc """
#   Prints a summary of the scan results.
#   """
#   def print_summary(scan_results) do
#     IO.puts("\n=== DOM Security Scan Results ===\n")
#
#     IO.puts("DOM Manipulations (#{length(scan_results.dom_manipulations)}):")
#     Enum.each(scan_results.dom_manipulations, fn item ->
#       IO.puts("  - [Line #{item.line}] #{item.type}: #{truncate(item.code, 80)}")
#     end)
#
#     IO.puts("\nHTML Templates (#{length(scan_results.html_templates)}):")
#     Enum.each(scan_results.html_templates, fn item ->
#       IO.puts("  - [Line #{item.line}] #{item.type}: #{truncate(item.code, 80)}")
#     end)
#
#     IO.puts("\nDOM Sinks (#{length(scan_results.dom_sinks)}):")
#     Enum.each(scan_results.dom_sinks, fn item ->
#       IO.puts("  - [Line #{item.line}] #{item.type} (Risk: #{item.risk}): #{truncate(item.code, 80)}")
#     end)
#
#     sensitive_comments = Enum.filter(scan_results.comments, & &1.sensitive)
#     IO.puts("\nPotentially Sensitive Comments (#{length(sensitive_comments)}/#{length(scan_results.comments)}):")
#     Enum.each(sensitive_comments, fn item ->
#       IO.puts("  - [Line #{item.line}] #{item.type}: #{truncate(item.content, 80)}")
#     end)
#
#     IO.puts("\n=== End of DOM Security Scan ===")
#   end
#
#   # Helper functions
#
#   # Identifies potential sources of external data in the code
#   defp identify_external_sources(text) do
#     source_patterns = [
#       ~r/(location\.(?:search|hash|href|pathname))/i,
#       ~r/(document\.(?:URL|documentURI|referrer))/i,
#       ~r/((?:local|session)Storage\.getItem\([^)]+\))/i,
#       ~r/(document\.cookie)/i,
#       ~r/(document\.getElementById\([^)]+\)\.value)/i,
#       ~r/(\$\(['"](?:#[^'"]+)['"](?:\.val\(\)|\.text\(\)|\.html\(\)))/i,
#       ~r/(new URLSearchParams\()/i,
#       ~r/(fetch\([^)]+\))/i,
#       ~r/(XMLHttpRequest)/i,
#       ~r/(\.ajax\()/i
#     ]
#
#     Enum.flat_map(source_patterns, fn pattern ->
#       Regex.scan(pattern, text, capture: :first)
#       |> Enum.map(fn [source] -> source end)
#     end)
#   end
#
#   # Detects risky Function constructor usage by looking for patterns where
#   # external data might be passed to the constructor
#   defp detect_risky_function_constructors(text, external_sources) do
#     # First, find all Function constructor usages
#     function_constructor_pattern = ~r/new\s+Function\s*\(([^)]*)\)/i
#
#     Regex.scan(function_constructor_pattern, text, return: :index)
#     |> Enum.map(fn indices ->
#       # Extract the full constructor call using the first index pair
#       # This handles cases where multiple capture groups are returned
#       {start, length} = List.first(indices)
#
#       constructor_code = binary_part(text, start, length)
#
#       # Get the line number
#       line = find_line_number(text, constructor_code)
#
#       # Extract the arguments
#       args_match = Regex.run(~r/new\s+Function\s*\(([^)]*)\)/i, constructor_code, capture: :all_but_first)
#       args = if args_match, do: List.first(args_match), else: ""
#
#       # Check if this usage is risky by looking for external sources in the arguments
#       # or in the surrounding context (20 characters before and after)
#       context_start = max(0, start - 20)
#       context_length = min(String.length(text) - context_start, length + 40)
#       context = binary_part(text, context_start, context_length)
#
#       is_risky = risky_function_constructor?(args, context, external_sources)
#
#       if is_risky do
#         %{
#           type: "Function constructor (risky)",
#           code: constructor_code,
#           line: line,
#           risk: "High",
#           context: context
#         }
#       else
#         nil
#       end
#     end)
#     |> Enum.reject(&is_nil/1)
#   end
#
#   # Determines if a Function constructor usage is risky based on its arguments and context
#   defp risky_function_constructor?(args, context, external_sources) do
#     # Check if any external source is directly used in the arguments
#     direct_usage = Enum.any?(external_sources, fn source ->
#       String.contains?(args, source)
#     end)
#
#     # Check for variable usage that might contain external data
#     # This is a heuristic - we look for variables that are assigned external data
#     # and then used in the Function constructor
#     indirect_usage = Enum.any?(external_sources, fn source ->
#       # Look for patterns like: var x = location.search; ... new Function(x)
#       var_assignment = Regex.run(~r/(?:var|let|const)\s+(\w+)\s*=\s*#{Regex.escape(source)}/i, context)
#
#       if var_assignment do
#         var_name = Enum.at(var_assignment, 1)
#         # Check if this variable is used in the Function constructor arguments
#         String.contains?(args, var_name)
#       else
#         false
#       end
#     end)
#
#     # Check for other risky patterns
#     other_risky_patterns = [
#       # JSON.parse of external data
#       ~r/JSON\.parse\([^)]*(?:localStorage|sessionStorage|cookie|location|document\.URL)/i,
#       # Decoding of URL components
#       ~r/decodeURI(?:Component)?\([^)]*(?:location|document\.URL|search|hash)/i,
#       # Passing user input directly
#       ~r/getElementById\([^)]+\)\.value/i
#     ]
#
#     other_risks = Enum.any?(other_risky_patterns, fn pattern ->
#       Regex.match?(pattern, context)
#     end)
#
#     # Also consider it risky if it appears in an event handler for messages
#     in_message_handler = Regex.match?(~r/addEventListener\(['"](message|postMessage)['"][^{]*\{[^}]*new\s+Function/is, context)
#
#     direct_usage || indirect_usage || other_risks || in_message_handler
#   end
#
#   defp find_line_number(text, substring) do
#     case :binary.match(text, substring) do
#       {pos, _} ->
#         text_before = binary_part(text, 0, pos)
#         String.split(text_before, "\n") |> length()
#       :nomatch ->
#         0
#     end
#   end
#
#   defp assess_risk(type) do
#     high_risk = ["eval()", "Function constructor (risky)", "setTimeout with string",
#                 "setInterval with string", "document.write"]
#     medium_risk = ["innerHTML assignment", "outerHTML assignment", "insertAdjacentHTML",
#                   "location object", "document.URL", "document.cookie"]
#
#     cond do
#       Enum.member?(high_risk, type) -> "High"
#       Enum.member?(medium_risk, type) -> "Medium"
#       true -> "Low"
#     end
#   end
#
#   defp contains_sensitive_info?(content) do
#     sensitive_patterns = [
#       ~r/password/i,
#       ~r/api\s*key/i,
#       ~r/secret/i,
#       ~r/token/i,
#       ~r/auth/i,
#       ~r/credential/i,
#       ~r/TODO/i,
#       ~r/FIXME/i,
#       ~r/HACK/i,
#       ~r/XXX/i,
#       ~r/BUG/i,
#       ~r/SECURITY/i
#     ]
#
#     Enum.any?(sensitive_patterns, fn pattern ->
#       Regex.match?(pattern, content)
#     end)
#   end
#
#   defp truncate(text, max_length) do
#     if String.length(text) > max_length do
#       String.slice(text, 0, max_length) <> "..."
#     else
#       text
#     end
#   end
# end
