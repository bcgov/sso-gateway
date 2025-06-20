# Secure Web Application Architecture with BC Government Keycloak SSO

This repository contains the configurations and Kubernetes Helm charts to deploy an Nginx reverse proxy with SSO (Single Sign-On) gateway client integrated with the BC Government's [Common Hosted Single Sign-On (CSS)](https://bcgov.github.io/sso-requests/).

-----

## Project Overview

This project provides a secure and managed way to expose a **web application** through an Nginx reverse proxy, which enforces authentication via a dedicated SSO Gateway Client. The SSO Client uses **Redis** for storing user session data. All components are deployed within an OpenShift environment using Helm charts.

This architecture is designed to provide a secure, high-performance, and scalable foundation for web applications. By utilizing NGINX as a reverse proxy, we centralize request handling, enable SSL termination, and facilitate load balancing. The Node.js application focuses on business logic, offloading authentication to the BC Government's Common Keycloak service via OpenID Connect (OIDC). User sessions are managed efficiently and externalized to Redis, allowing for seamless scaling and resilience.

## Components

### NGINX Reverse Proxy
Entry point for incoming requests. Provides SSL/TLS Termination to handle HTTPS encryption and decryption; Directs incoming traffic

### BC Government Common Keycloak Service (OIDC)
Centralized Identity and Access Management (IAM) provider for BC Government applications. Uses OpenID Connect (OIDC) protocol used for secure communication and identity verification.

### NodeJS Client Application

OIDC Client that initiates authentication requests to Keycloak and processes the authorization codes/tokens returned; Exposes APIs for frontend consumption. Creates and manages user sessions, storing essential session data (e.g., user ID, access token, refresh token) in Redis.

### Redis Session Store
External, high-performance, in-memory data store for user sessions.


## Architecture

```mermaid
graph TD
    subgraph Internet
        User_Browser
    end

    subgraph Private Cloud OpenShift
        NGINX_Reverse_Proxy
        subgraph Client or Server Applications
            NodeJS_App_1[Application 1]
            NodeJS_App_2[Application 2]
            NodeJS_App_N[Application 3]
        end
        Redis_Session_Store
    end

    subgraph BC Gov SSO Service
        BC_Gov_Keycloak_Service(BC Gov SSO)
    end

    User_Browser -- HTTPS Request --> NGINX_Reverse_Proxy
    NGINX_Reverse_Proxy -- Proxy Pass --> NodeJS_App_1
    NGINX_Reverse_Proxy -- Proxy Pass --> NodeJS_App_2
    NGINX_Reverse_Proxy -- Proxy Pass --> NodeJS_App_N

    NodeJS_App_1 -- OIDC Request (Redirect) --> User_Browser
    User_Browser -- Authenticates --> BC_Gov_Keycloak_Service

    BC_Gov_Keycloak_Service -- OIDC Auth Code (Redirect) --> NGINX_Reverse_Proxy
    User_Browser -- OIDC Auth Code --> NGINX_Reverse_Proxy

    NGINX_Reverse_Proxy -- OIDC Token Exchange --> BC_Gov_Keycloak_Service
    BC_Gov_Keycloak_Service -- ID & Access Tokens --> NGINX_Reverse_Proxy

    NodeJS_App_1 -- Store Session --> Redis_Session_Store
    NodeJS_App_2 -- Retrieve Session --> Redis_Session_Store
    NodeJS_App_N -- Retrieve Session --> Redis_Session_Store

    NodeJS_App_1 -- Set Session Cookie --> NGINX_Reverse_Proxy
    User_Browser -- Requests (with Session) --> NGINX_Reverse_Proxy
    NodeJS_App_2 -- Retrieve Session Data --> Redis_Session_Store
    NodeJS_App_2 -- Application Response --> NGINX_Reverse_Proxy
    NGINX_Reverse_Proxy -- HTTPS Response --> User_Browser

```


### Authentication and Session Flow

1.  **Initial Request:** Send HTTPS request to application's domain (e.g., `https://myapp.gov.bc.ca`).
2.  **NGINX Proxy:** NGINX receives the request, terminates SSL, and forwards it to a Node.js application instance (via a load balancer, if present).
3.  **Authentication Check (Node.js):** The Node.js application checks for an existing, valid session (e.g., via a session cookie).
4.  **Redirect to Keycloak:** If no valid session exists, the Node.js application initiates an OIDC authorization code flow by redirecting the user's browser to the BC Government's Keycloak login page, including `client_id`, `redirect_uri`, `scope`, and `response_type`.
5.  **Keycloak Authentication:** The user logs in to Keycloak using their BCeID or other supported credentials.
6.  **Authorization Code Grant:** Upon successful authentication, Keycloak redirects the user's browser back to the Node.js application's `redirect_uri` with an authorization code.
7.  **Token Exchange (Node.js):** The Node.js application receives the authorization code and exchanges it directly with Keycloak (server-to-server) for ID, Access, and Refresh Tokens. This exchange is secure and bypasses the user's browser.
8.  **Session Creation (Node.js & Redis):** The Node.js application validates the received tokens. It then creates a server-side session, storing relevant user details (from the ID Token), the Access Token, and the Refresh Token in Redis, associated with a unique session ID.
9.  **Session Cookie:** The Node.js application sends a `Set-Cookie` header to the user's browser containing the session ID (e.g., `connect.sid`). This cookie is typically `HttpOnly` and `Secure`.
10. **Authorized Access:** For all subsequent requests within the session, the user's browser sends the session ID cookie.
11. **Session Retrieval (Node.js & Redis):** The Node.js application retrieves the session data from Redis using the session ID from the cookie.
12. **Token Validation/Refresh:** The Node.js application validates the Access Token. If expired, it uses the Refresh Token to obtain new Access and ID Tokens from Keycloak without user re-authentication.
13. **Resource Access:** If the session and tokens are valid, the Node.js application grants access to the requested resources.

### Setup Considerations

#### BC Gov Keycloak Integration

  * **Client Registration:** Your application must be registered as a client within the BC Government's Keycloak realm. You will need to obtain a `client_id` and `client_secret`.
  * **Redirect URIs:** Configure all valid `redirect_uri`s for your application in Keycloak (e.g., `https://myapp.gov.bc.ca/auth/callback`).
  * **Public/Confidential Client:** For Node.js (server-side), it's typically configured as a `confidential` client as it can securely store the `client_secret`.
  * **Scope:** Define the necessary OIDC scopes (e.g., `openid`, `profile`, `email`) your application requires.

#### NGINX Configuration

  * **SSL/TLS:** Configure SSL certificates (e.g., from Let's Encrypt or BC Gov provided certificates) for your domain.
  * **Proxy Pass:** Set up `proxy_pass` directives to forward requests to your Node.js application instances (or a load balancer).
  * **HTTP Headers:** Ensure correct `X-Forwarded-For`, `X-Real-IP`, and `X-Forwarded-Proto` headers are passed to Node.js for accurate request context.
  * **Error Pages:** Configure custom error pages.


### SSO Client Configuration

  * **OIDC Client Library:** Use a robust OIDC client library (uses `openid-client`) to handle the OIDC flow.
  * **Environment Variables:** Store sensitive configuration like Keycloak `client_id`, `client_secret`, and Redis connection details as environment variables.
  * **Session Middleware:** Integrate a session management middleware (e.g., `express-session` with a Redis store like `connect-redis`).
  * **Token Management:** Implement logic to store, validate, and refresh Access Tokens using the Refresh Token.

-----


## Architecture

The application stack consists of the following components and flow:


```mermaid

sequenceDiagram
    actor User
    participant Browser
    participant OCR as OpenShift Route
    participant Nginx as Nginx Proxy
    participant SSOC as SSO Gateway Client
    participant KC as Keycloak (IdP)
    participant Redis
    participant WA as Web Application


        Browser->>OCR: 1. Request https:app-host
        OCR->>Nginx: 2. Proxy HTTP request<br/>(X-Forwarded-Proto: https,<br/> Host: <app-host>)
        Nginx->>SSOC: 3. Authentication Subrequest to /auth/
        activate Nginx
        activate SSOC
        SSOC->>KC: 4. Authorization Request<br/>(redirect_uri=https://<app-host>/sso)
        activate KC
        KC-->>SSOC: 5. Redirect to Keycloak Login Page URL
        deactivate SSOC
        Nginx-->>Browser: 6. HTTP 302 Redirect to Keycloak Login Page
        deactivate Nginx

        Browser->>KC: 7. User authenticates via login form<br/>(submit credentials)
        KC->>KC: 8. Verify credentials & generate code
        KC-->>Browser: 9. HTTP 302 Redirect to redirect_uri<br/>(incl. auth code)<br/>(https://<app-host>/sso?code=...)

        Browser->>OCR: 10. Request https://<app-host>/sso?code=...
        OCR->>Nginx: 11. Proxy HTTP request to /sso
        activate Nginx
        Nginx->>SSOC: 12. Proxy request to /authn/callback<br/>(incl. auth code)
        activate SSOC
        SSOC->>KC: 13. Token Exchange Request<br/>(using auth code & client secret)
        activate KC
        KC-->>SSOC: 14. Access Token, ID Token, Refresh Token
        deactivate KC
        SSOC->>Redis: 15. Store Session Data (ID Token, etc.)
        activate Redis
        Redis-->>SSOC: 16. Session stored
        deactivate Redis
        SSOC-->>Nginx: 17. Authentication Success / Redirect to original URL<br/>(e.g., set session cookie, 302 to /)
        deactivate SSOC
        Nginx-->>Browser: 18. HTTP 302 Redirect to original URL (e.g., https://<app-host>/)
        deactivate Nginx
 


        Browser->>OCR: 19. Request https://<app-host>/<path>
        OCR->>Nginx: 20. Proxy HTTP request<br/>(incl. Nginx Session Cookie)
        activate Nginx
        Nginx->>SSOC: 21. Authentication Subrequest to /auth/<br/>(incl. Nginx Session Cookie)
        activate SSOC
        SSOC->>Redis: 22. Validate Session Data
        activate Redis
        Redis-->>SSOC: 23. Session Data Retrieved (Valid)
        deactivate Redis
        SSOC-->>Nginx: 24. Authentication Success (HTTP 200)
        deactivate SSOC
        Nginx->>WA: 25. Proxy request to Web Application
        activate WA
        WA-->>Nginx: 26. Web Application Content
        deactivate WA
        Nginx-->>Browser: 27. Return Web Application Content
        deactivate Nginx


```
-----

## Prerequisites

  * An active OpenShift cluster (or Kubernetes cluster with Ingress/Routes configured).
  * `oc` CLI tool (for OpenShift) or `kubectl` CLI tool (for Kubernetes).
  * Helm v3 installed.
  * Access to the OpenShift project/namespace where the application will be deployed (`abcdef-dev` as used in examples).
  * A configured Keycloak Realm and Client for your SSO Gateway Client.

-----

## Deployment with Helm

This repository contains Helm charts for deploying the application components.

No problem! Setting up configuration values is a critical part of any deployment. I'll add a new section to the README specifically for configuring the SSO Client, detailing both its direct environment variables and the values retrieved from Vault.

---

## 4.1 SSO Client Configuration Values

The SSO Gateway Client requires a set of configuration values to properly connect to Keycloak, manage sessions with Redis, and integrate with the Nginx proxy. These values are primarily sourced from **environment variables** and a **JSON configuration string from Vault**.

### Environment Variables (Directly Configurable)

Many of the SSO Client's settings can be overridden or directly set via environment variables. These are typically managed within the Helm chart's `values.yaml` for the `sso-gateway-client` deployment.

* `NGINX_PROXY_URL`: (Optional) The URL of the Nginx proxy. Defaults to `http://localhost:8080`.
* `SSO_CLIENT_HOST`: (Optional) The hostname the SSO Client itself listens on. Defaults to `localhost`.
* `SSO_CLIENT_PORT`: (Optional) The port the SSO Client itself listens on. Defaults to `3000`.
* `SSO_REDIS_SESSION_STORE_URL`: The connection URL for the Redis session store. Defaults to `redis://localhost:6379`. **In OpenShift, this should be set to `redis://sso-gateway-redis-svc:6379`**.
* `SSO_REDIS_CONNECT_PASSWORD`: The password for connecting to Redis. This should **not** be set directly but injected from a Kubernetes Secret populated from Vault (see below).
* `SSO_LOGOUT_REDIRECT_URI`: The URL to redirect to after a local SSO client logout. Defaults to `https://gov.bc.ca`.
* `SM_LOGOUT_URL`: The URL for the government's Single Sign-On (SM) logout endpoint. Defaults to `https://logon.gov.bc.ca/clp-cgi/logoff.cgi`.

### Vault-Managed Configuration

Sensitive and environment-specific Keycloak and session secrets are managed securely in **Vault**. These values are retrieved at runtime or injected into the SSO Client's environment via Kubernetes Secrets.

1.  **`redis-password/password`**:
    * This Vault key stores the password used by the SSO Client to authenticate with the Redis session store.
    * It should contain a plain string representing the Redis password.
    * **Usage**: This value is typically retrieved by an init container or directly mounted as an environment variable in the SSO Client pod from a Kubernetes Secret (e.g., `SSO_REDIS_CONNECT_PASSWORD`).

2.  **`keycloak-config/config`**:
    * This Vault key stores a **JSON string** containing core Keycloak and application hostname configurations. This allows for environment-specific settings to be centrally managed.
    * The JSON string **must be on a single line** and conform to the following array of objects structure:

    ```json
    [{"hostname":"example.app.gov.bc.ca","keycloak":{"confidential-port":0,"auth-server-url":"https://dev.loginproxy.gov.bc.ca","realm":"standard","ssl-required":"external","client-id":"example-app-client-id", "client-secret":"hafoC8ijIHaSWOvizoWl", "session-secret":"bA10truswI1a7rudRlYL"}}]
    ```
    * **Fields within the `keycloak-config/config` JSON:**
        * `hostname`: The public, external hostname of your application (e.g., `example.app.gov.bc.ca`). This is crucial for constructing the `SSO_REDIRECT_URL`.
        * `keycloak.auth-server-url`: The base URL of your Keycloak authentication server (e.g., `https://dev.loginproxy.gov.bc.ca`).
        * `keycloak.realm`: The Keycloak realm your client belongs to (e.g., `standard`).
        * `keycloak.ssl-required`: Keycloak's SSL requirement for this client. Set to `"external"` or `"all"` for HTTPS environments.
        * `keycloak.client-id`: The client ID registered in Keycloak for your SSO Gateway Client.
        * `keycloak.client-secret`: The client secret for your Keycloak client. **This is a sensitive value**.
        * `keycloak.session-secret`: A strong, random secret used by the SSO Client for session encryption/signing. **This is a sensitive value**.
        * `keycloak.confidential-port`: (Often `0` for proxies) The port on the client where confidential traffic is expected.

---

### Configuration (`values.yaml`)

Each Helm chart (e.g., `sso-gateway-nginx`, `sso-gateway-client`, `sso-gateway-redis`) will have its own `values.yaml` file. You should review and customize these according to your environment.

**Common `values.yaml` Parameters to Configure:**

  * **`image.repository` / `image.tag`**: Docker image details for each component.
  * **`replicaCount`**: Number of pod replicas.
  * **`service.port`**: The service port that the Kubernetes Service exposes.
  * **`container.port`**: The internal port that the application container listens on.
  * **`resources`**: CPU/Memory limits and requests.
  * **`ingress.host` / `route.host`**: The external hostname (e.g., `example.app.gov.bc.ca`) for the OpenShift Route.
  * **Nginx Specific (`sso-gateway-nginx/values.yaml`):**
      * `configMap.data.default_conf`: The content of your `default.conf` Nginx configuration. This will be mounted as a ConfigMap.
  * **SSO Client Specific (`sso-gateway-client/values.yaml`):**
      * `env`: Environment variables for the SSO client, including:
          * `KEYCLOAK_AUTH_SERVER_URL`: Your Keycloak URL.
          * `KEYCLOAK_REALM`: Your Keycloak realm.
          * `KEYCLOAK_RESOURCE`: Your Keycloak client ID.
          * `KEYCLOAK_CREDENTIALS_SECRET`: If using client secret.
          * **Crucially**: `KEYCLOAK_PUBLIC_CLIENT` (often `true` if your Nginx handles secrets) or `KEYCLOAK_SSL_REQUIRED` (`external` or `all` to ensure HTTPS redirect URIs).
          * **Important**: Any `BASE_URL` or `APPLICATION_URL` setting for the SSO client that helps it construct correct `redirect_uri`s using `https://<your-public-host>`.
          * **Redis Integration**:
              * `REDIS_HOST`: `sso-gateway-redis-svc` (Kubernetes Service name for Redis).
              * `REDIS_PORT`: `6379`.
              * `REDIS_PASSWORD`: Authentication used by default.

### Installation

1.  **Customize `values.yaml`:**
    Update the chart default values and adjust their respective `values.yaml` files.

2.  **Deploy SSO Gateway:**

    ```bash
    helm install sso-gateway -f ./values.yaml oci://ghcr.io/bcgov/sso-gateway/sso-gateway
    ```

3.  **Upgrade Helm Chart:**

    ```bash
    helm upgrade sso-gateway -f ./values.yaml oci://ghcr.io/bcgov/sso-gateway/sso-gateway
    ```

-----

## Container Details

### Nginx Proxy Container (`sso-gateway-nginx`)

  * **Purpose:** Acts as the public-facing gateway for `example.app.gov.bc.ca`. It terminates HTTP from the OpenShift router (after TLS termination), enforces authentication via an `auth_request` subrequest to the SSO Gateway Client, and reverse proxies authenticated traffic to the **web application**.

  * **Key Configuration (`/etc/nginx/conf.d/default.conf` - managed by ConfigMap):**

    ```nginx
    server {
        listen 8081; # Main application traffic port (internal to OpenShift)
        listen [::]:8081;
        server_name example.app.gov.bc.ca;
        error_page 401 403 = @login_required; # Directs unauthenticated requests to login flow

        port_in_redirect off; # CRITICAL: Prevents Nginx from adding :8081 to redirects

        # Essential headers for correct proxying and SSO
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $http_x_forwarded_proto; # Pass original scheme from router
        proxy_set_header Host $http_host; # Pass original Host header from router

        proxy_connect_timeout 75s;
        proxy_send_timeout 75s;
        proxy_read_timeout 300s;

        # Main application block - requires authentication
        location / {
          auth_request /auth/; # Triggers subrequest for authentication
          auth_request_set $auth_status $upstream_status;
          proxy_set_header Host example.app.gov.bc.ca; # Override Host for web application
          proxy_pass http://<web-app-service-name>/; # Proxy to web application service
          proxy_redirect default; # Rewrites Location headers from web application
        }

        # Internal authentication subrequest location
        location /auth/ {
          internal; # Cannot be accessed directly from outside
          proxy_pass_request_body off;
          proxy_set_header Content-Length "";
          proxy_set_header Authorization $http_authorization;
          proxy_pass_header Authorization;
          proxy_pass http://sso-gateway-client-svc/; # Proxy to SSO Gateway Client service
          proxy_redirect default; # Rewrites Location headers from SSO Gateway Client
        }

        # SSO Login initiation
        location /sso-login {
          proxy_set_header Host $host; # Use actual incoming Host header
          proxy_pass http://sso-gateway-client-svc/authn; # Direct to SSO Gateway Client's auth endpoint
          proxy_redirect default; # Rewrites Location headers from SSO Gateway Client
        }

        # SSO Callback endpoint
        location /sso {
          proxy_set_header Host $host; # Use actual incoming Host header
          proxy_pass http://sso-gateway-client-svc/authn/callback; # Direct to SSO Gateway Client's callback
          proxy_redirect default; # Rewrites Location headers from SSO Gateway Client
        }

        # Named location for handling 401/403 (unauthenticated) errors
        location @login_required {
          return 302 /sso-login?relay=$request_uri; # Redirects to SSO login page, using relative path
        }

        # Health check endpoint for Kubernetes Liveness/Readiness probes
        location /health {
            access_log off;
            add_header Content-Type text/plain;
            return 200 "OK\n";
        }
    }
    ```

  * **Ports:**

      * **Container Port 8081:** For application traffic.
      * **Container Port 8080:** For health checks (`/health` endpoint).

  * **Health Checks:**

      * The Nginx container includes a `/health` endpoint on port 8080 for Kubernetes probes.

### SSO Gateway Client Container (`sso-gateway-client-svc`)

  * **Purpose:** This application acts as an OAuth/OpenID Connect client (e.g., a Keycloak adapter or a custom client application). It handles the communication with the Keycloak IdP, manages tokens, and provides an authentication endpoint for Nginx to use. It uses Redis for session storage.
  * **Key Configuration (Environment Variables):**
      * **`KEYCLOAK_AUTH_SERVER_URL`**: `https://<your-keycloak-url>/auth`
      * **`KEYCLOAK_REALM`**: The name of your Keycloak realm.
      * **`KEYCLOAK_RESOURCE`**: Your Keycloak client ID (e.g., `sso-gateway-client`).
      * **`KEYCLOAK_CREDENTIALS_SECRET`**: (If using client secret, stored as Kubernetes secret).
      * **Redis Connection**:
          * `SESSION_STORE_TYPE`: `redis`
          * `REDIS_HOST`: `sso-gateway-redis-svc` (the Kubernetes Service name for your Redis instance).
          * `REDIS_PORT`: `6379`
          * `REDIS_PASSWORD`: (Optional, if Redis requires a password).
      * **CRITICAL: External URL/Scheme Configuration:** The SSO client *must* be configured to correctly build the `redirect_uri` and other public URLs using `https://example.app.gov.bc.ca`. This typically involves:
          * Setting a `KEYCLOAK_SSL_REQUIRED` environment variable to `external` or `all`.
          * Ensuring the application properly consumes `X-Forwarded-Proto` and `Host` headers sent by Nginx to determine its public URL.
          * Some clients require an explicit `KEYCLOAK_FRONTEND_URL` or `APPLICATION_BASE_URL` if they cannot reliably infer it from headers.
  * **Keycloak Client Configuration (in Keycloak IdP):**
      * The Keycloak client for `sso-gateway-client` **MUST** have the exact `Valid Redirect URIs` defined, including the scheme. For this setup, it's typically:
          * `https://example.app.gov.bc.ca/sso`
          * `https://example.app.gov.bc.ca/*` (if using wildcards, but specific is preferred)

### Redis Container

  * **Purpose:** Provides a high-performance in-memory data store used by the SSO Gateway Client for session management (e.g., Spring Session with Redis).
  * **Configuration:** Typically minimal beyond setting up a Kubernetes Service. Ensure `sso-gateway-redis-svc` is the correct Service name that the SSO Gateway Client can resolve.
  * **Persistence:** Consider adding persistent storage for Redis if session durability is critical across pod restarts.

### Web Application Container

  * **Purpose:** This is the actual web application content being protected. It expects to be served by the Nginx proxy (e.g., via `http://<web-app-service-name>/` its internal Kubernetes Service name).
  * **Configuration:** Typically requires minimal changes to interact with this setup, as Nginx handles the authentication layer.

-----

## OpenShift Route Configuration

The OpenShift Route exposes your Nginx proxy to the public internet and handles TLS termination.

  * **Hostname:** `example.app.gov.bc.ca`
  * **Path:** `/` (or whatever base path you use)
  * **Target Service:** `sso-gateway-nginx-svc`
  * **Target Port:** `8081`.
  * **TLS Termination:** **Edge** or **Re-encrypt**.
      * **Edge (Recommended for this setup):** Router terminates TLS, sends plain HTTP to Nginx on 8081. Nginx receives `X-Forwarded-Proto: https`.
      * **Re-encrypt:** Router terminates TLS, re-encrypts, sends HTTPS to Nginx on 8081. Nginx would need `listen 8081 ssl;` and certificates configured. (Less common for this pattern).
      * **Passthrough:** Router passes encrypted traffic directly. Nginx *must* terminate TLS. (Not used here).

-----

## Keycloak / Identity Provider (IdP) Configuration

Ensure your Keycloak Realm and Client are correctly set up:

  * **Client ID:** Matches `KEYCLOAK_RESOURCE` in your SSO client (e.g., `sso-gateway-client`).
  * **Client Secret:** If your SSO client is confidential, configure this securely.
  * **Access Type:** Typically `confidential` or `public` depending on your SSO client's design.
  * **Standard Flow Enabled:** Yes.
  * **Valid Redirect URIs:** **CRITICAL\!** This must exactly match the `redirect_uri` that your SSO Gateway Client sends to Keycloak.
      * Example: `https://example.app.gov.bc.ca/sso`
      * Ensure no typos, no `http://` if your public endpoint is `https://`, and no extraneous path segments.
  * **Web Origins:** `https://example.app.gov.bc.ca` (or `*` for broader testing, but restrict in production).

-----

## Troubleshooting Common Issues

When debugging, always remember to:

  * **`oc logs <pod-name>`:** Check logs of Nginx, SSO client, Redis, and your web application.
  * **`oc describe pod <pod-name>`:** Check for events, readiness/liveness probe status.
  * **`oc get endpoints <service-name>`:** Ensure your Service has correctly found your pod endpoints and exposed the correct ports.
  * **`oc get networkpolicy -n <namespace>`:** Review any active NetworkPolicies that might be blocking traffic.
  * **Curl from inside the cluster:** Use `oc rsh <any-pod>` or a debug pod (`oc debug -it --image=registry.access.redhat.com/ubi8/ubi-minimal`) to `curl -vk` your services internally (e.g., `http://sso-gateway-nginx-svc:8081/`). This isolates issues to internal Kubernetes networking.
  * **Clear Browser Cache/Cookies:** Always do this when debugging redirects and SSO flows.

### `404 Not Found` from Nginx

  * **Symptom:** Curling `http://sso-gateway-nginx-svc:8080/` (or similar) from inside the namespace gets an Nginx 404, with logs showing `"index.html" is not found`.
  * **Reason:** 
  * **Solution:** 

-----

## Contributing

TBD -- Instructions on how to contribute to this project.

## License

MIT License (2025)

