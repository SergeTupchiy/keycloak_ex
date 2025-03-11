defmodule KeycloakEx.Client.User do
  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @otp_app opts[:otp_app]
      use OAuth2.Strategy

      require Logger

      def config() do
        Application.get_env(@otp_app, __MODULE__, [])
      end

      @spec new :: OAuth2.Client.t()
      def new do
        new_from_conf(config())
      end

      def authorize_url!(params \\ []) do
        conf = config()

        conf
        |> maybe_put_public_auth_uri()
        |> new_from_conf()
        |> put_param(:scope, conf[:scope])
        |> OAuth2.Client.authorize_url!(params)
      end

      def get_token!(params \\ [], headers \\ []) do
        OAuth2.Client.get_token!(new(), params, headers)
      end

      @impl true
      def authorize_url(client, params \\ []) do
        OAuth2.Strategy.AuthCode.authorize_url(client, params)
      end

      @impl true
      def get_token(client, params, headers) do
        client
        |> put_header("Accept", "application/json")
        |> OAuth2.Strategy.AuthCode.get_token(params, headers)
      end

      def refresh_token(t) do
        new()
        |> Map.put(:token, t)
        |> OAuth2.Client.refresh_token()
      end

      def introspect(access_token) do
        conf = config()

        introspect_val = %{
          client_secret: conf[:client_secret],
          client_id: conf[:client_id],
          token: access_token
        }

        Logger.debug(
          "[KeycloakEx.Client.User][introspect] - Request - #{inspect(introspect_val)}"
        )

        resp =
          OAuth2.Client.post(
            new(),
            "#{conf[:host_uri]}/realms/#{conf[:realm]}/protocol/openid-connect/token/introspect",
            introspect_val,
            [
              {"Accept", "application/json"},
              {"Content-Type", "application/x-www-form-urlencoded"}
            ]
          )

        Logger.debug("[KeycloakEx.Client.User][introspect] - Response - #{inspect(resp)}")

        case resp do
          {:ok, %{body: body}} ->
            {:ok, body}

          err ->
            err
        end
      end

      defp new_from_conf(conf) do
        OAuth2.Client.new(
          strategy: __MODULE__,
          client_id: conf[:client_id],
          client_secret: conf[:client_secret],
          redirect_uri: "#{conf[:site]}/login_cb",
          site: conf[:site],
          authorize_url: "#{conf[:host_uri]}/realms/#{conf[:realm]}/protocol/openid-connect/auth",
          token_url: "#{conf[:host_uri]}/realms/#{conf[:realm]}/protocol/openid-connect/token"
        )
        |> OAuth2.Client.put_serializer("application/json", Jason)
      end

      defp maybe_put_public_auth_uri(conf) do
        case conf[:public_uri] do
          nil -> conf
          uri -> Keyword.put(conf, :host_uri, uri)
        end
      end
    end
  end
end
