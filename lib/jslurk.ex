# lib/jshound.ex
defmodule JSLurk do
  @moduledoc """
  JSLurk is a bug bounty tool for extracting interesting information from JavaScript files.
  """

  alias JSLurk.Scanner

  @doc """
  Scans a URL for interesting information.
  """
  def scan_url(url, verbose \\ false) do
    Scanner.scan_url(url, verbose)
  end

  @doc """
  Scans JavaScript content for interesting information.
  """
  def scan_content(content, url \\ "unknown", status_code \\ 200) do
    Scanner.scan_content(url, content, status_code)
  end
end
