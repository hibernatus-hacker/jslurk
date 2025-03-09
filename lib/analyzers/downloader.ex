
defmodule JSLurk.Downloader do
  @moduledoc """
  Module for downloading JavaScript files to a local directory.
  Files are organized by URL, with each URL having its own folder.
  """

  @doc """
  Saves JavaScript content to a file in a URL-specific directory.
  If content is nil, downloads the file from the URL.
  Returns {:ok, path} on success or {:error, reason} on failure.
  """
  def save(url, content, base_directory) do
    # Create URL-specific directory
    url_directory = create_url_directory(url, base_directory)

    # Generate a filename based on the URL
    filename = generate_filename(url)
    path = Path.join(url_directory, filename)
    absolute_path = Path.expand(path)

    if content do
      # We already have the content, just save it
      case File.write(path, content) do
        :ok ->
          IO.puts("Saved file:")
          IO.puts("  URL: #{url}")
          IO.puts("  To:  #{absolute_path}")
          {:ok, path}
        {:error, reason} ->
          IO.puts("Error writing file:")
          IO.puts("  URL: #{url}")
          IO.puts("  Error: #{inspect(reason)}")
          {:error, "Failed to write file: #{inspect(reason)}"}
      end
    else
      # We don't have the content, need to download it
      download_and_save(url, path, absolute_path)
    end
  end

  @doc """
  Creates a directory structure based on the URL.
  Returns the path to the URL-specific directory.
  """
  def create_url_directory(url, base_directory) do
    uri = URI.parse(url)

    # Extract the host (domain)
    host = uri.host || "unknown_host"

    # Create a sanitized directory name from the host
    host_dir = sanitize_directory_name(host)

    # Create the full directory path
    url_directory = Path.join(base_directory, host_dir)

    # Create the directory if it doesn't exist
    case File.mkdir_p(url_directory) do
      :ok -> url_directory
      {:error, reason} ->
        IO.puts("Warning: Could not create directory #{url_directory}: #{inspect(reason)}")
        # Fall back to the base directory
        File.mkdir_p!(base_directory)
        base_directory
    end
  end

  @doc """
  Sanitizes a directory name to ensure it's safe for the filesystem.
  """
  def sanitize_directory_name(name) do
    # Replace unsafe characters with underscores
    # Also replace dots to avoid issues with hidden directories
    Regex.replace(~r/[^\w\s\-]/, name, "_")
  end

  defp download_and_save(url, path, absolute_path) do
    IO.puts("Downloading: #{url}")

    case HTTPoison.get(url, [], [
      timeout: 10000,
      recv_timeout: 10000,
      follow_redirect: true,
      max_redirect: 5
    ]) do
      {:ok, %{body: body, status_code: status_code}} when status_code in 200..299 ->
        case File.write(path, body) do
          :ok ->
            IO.puts("Download successful:")
            IO.puts("  URL: #{url}")
            IO.puts("  To:  #{absolute_path}")
            IO.puts("  Size: #{format_size(byte_size(body))}")
            {:ok, path}
          {:error, reason} ->
            IO.puts("Error writing file:")
            IO.puts("  URL: #{url}")
            IO.puts("  Error: #{inspect(reason)}")
            {:error, "Failed to write file: #{inspect(reason)}"}
        end

      {:ok, %{status_code: status_code}} ->
        IO.puts("Error downloading file:")
        IO.puts("  URL: #{url}")
        IO.puts("  HTTP Status: #{status_code}")
        {:error, "HTTP status #{status_code}"}

      {:error, %HTTPoison.Error{reason: reason}} ->
        IO.puts("Error downloading file:")
        IO.puts("  URL: #{url}")
        IO.puts("  Error: #{inspect(reason)}")
        {:error, "Download failed: #{inspect(reason)}"}
    end
  end

  @doc """
  Generates a safe filename from a URL.
  """
  def generate_filename(url) do
    uri = URI.parse(url)

    # Extract the path and remove leading slash
    path = uri.path || ""
    path = if String.starts_with?(path, "/"), do: String.slice(path, 1..-1//1), else: path

    # Extract the filename from the path
    filename = Path.basename(path)

    # If no filename or it doesn't end with .js, generate one
    if filename == "" or not String.ends_with?(filename, ".js") do
      # Create a hash of the URL to ensure uniqueness
      hash = :crypto.hash(:md5, url) |> Base.encode16(case: :lower) |> String.slice(0, 8)
      "script_#{hash}.js"
    else
      # Make sure the filename is safe
      sanitize_filename(filename)
    end
  end

  @doc """
  Sanitizes a filename to ensure it's safe for the filesystem.
  """
  def sanitize_filename(filename) do
    # Replace unsafe characters with underscores
    sanitized = Regex.replace(~r/[^\w\s\.\-]/, filename, "_")

    # Ensure it ends with .js
    if String.ends_with?(sanitized, ".js") do
      sanitized
    else
      sanitized <> ".js"
    end
  end

  @doc """
  Formats a file size in bytes to a human-readable format.
  """
  def format_size(bytes) when is_integer(bytes) do
    cond do
      bytes >= 1_000_000 -> "#{Float.round(bytes / 1_000_000, 2)} MB"
      bytes >= 1_000 -> "#{Float.round(bytes / 1_000, 2)} KB"
      true -> "#{bytes} bytes"
    end
  end
end
