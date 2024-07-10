defmodule WorkOS.JWTValidator do
  require Logger
  alias JOSE.JWT

  @jwks_url "https://api.workos.com/sso/jwks/#{WorkOS.client_id(WorkOS.client())}"

  def validate_access_token(access_token) do
    case fetch_jwks() do
      {:ok, jwks} ->
        case decode_and_verify(access_token, jwks) do
          {:ok, claims} -> validate_exp(claims)
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp fetch_jwks() do
    case HTTPoison.get(@jwks_url) do
      {:ok, %HTTPoison.Response{status_code: 200, body: body}} ->
        # IO.inspect(Jason.decode!(body)["keys"] |> List.first())
        {:ok, JOSE.JWK.from(Jason.decode!(body)["keys"] |> List.first())}

      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        {:error, "Failed to fetch JWKS. Status code: #{status_code}"}

      {:error, %HTTPoison.Error{reason: reason}} ->
        {:error, "Failed to fetch JWKS. Reason: #{reason}"}
    end
  end

  defp decode_and_verify(access_token, jwks) do
    case JOSE.JWT.verify_strict(jwks, ["RS256"], access_token) do
      {true, %JWT{fields: claims}, _} -> {:ok, claims}
      {false, _, _} -> {:error, "Invalid token"}
    end
  end

  defp validate_exp(claims) do
    exp = claims["exp"]

    if exp > System.os_time(:second) do
      {:ok, claims}
    else
      {:error, "Token expired"}
    end
  end
end
