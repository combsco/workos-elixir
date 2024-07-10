defmodule WorkOS.JWTValidator do
  require Logger
  alias Hex.HTTP
  alias JOSE.JWT

  @jwks_url "https://api.workos.com/sso/jwks/#{WorkOS.client_id(client)}"

  def validate_access_token(access_token) do
    case fetch_jwks() do
      {:ok, jwks} ->
        case decode_and_verify(access_token, jwks) do
          {:ok, claims} -> {:ok, claims}
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_jwks() do
    case HTTPoison.get(@jwks_url) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        {:ok, JOSE.JWK.from_map(%{"keys" => Jason.decode!(body)["keys"]})}

      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        {:error, "Failed to fetch JWKS. Status code: #{status_code}"}

      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, "Failed to fetch JWKS. Reason: #{reason}"}
    end
  end

  defp decode_and_verify(access_token, jwks) do
    case JOSE.JWT.verify(jwks, access_token) do
      {true, jwt, _} -> {:ok, JOSE.JWT.peek_payload(jwt)}
      {false, _, _} -> {:error, "Invalid token"}
    end
  end
end
