# SSO Gateway Client

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

## 6\. OpenShift Route Configuration

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

## 7\. Keycloak / Identity Provider (IdP) Configuration

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

## 8\. Troubleshooting Common Issues

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

## 9\. Contributing

TBD -- Instructions on how to contribute to this project.

## 10\. License

MIT License (2025)