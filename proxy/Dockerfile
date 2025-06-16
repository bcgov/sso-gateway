# Use the official NGINX stable image
FROM nginx:1.25-alpine

# Set working directory
WORKDIR /etc/nginx

# Remove default NGINX configuration
# We will not directly copy our nginx.conf into conf.d/default.conf
# Instead, we'll create a dedicated directory for ConfigMap mounting
RUN rm /etc/nginx/conf.d/default.conf

# Modify the main NGINX configuration to include files from the new directory
# This typically means adding an 'include' directive in /etc/nginx/nginx.conf
# However, the default NGINX Docker image already has 'include /etc/nginx/conf.d/*.conf;'
# So, we'll just mount our config *as* default.conf into the conf.d directory.
# This means our ConfigMap will provide the *content* of default.conf.

# client_body_temp_path  "/opt/bitnami/nginx/tmp/client_body" 1 2;
#     proxy_temp_path        "/opt/bitnami/nginx/tmp/proxy" 1 2;
#     fastcgi_temp_path      "/opt/bitnami/nginx/tmp/fastcgi" 1 2;
#     scgi_temp_path         "/opt/bitnami/nginx/tmp/scgi" 1 2;
#     uwsgi_temp_path        "/opt/bitnami/nginx/tmp/uwsgi" 1 2;

#     sendfile           on;
#     tcp_nopush         on;
#     tcp_nodelay        off;
#     gzip               on;
#     gzip_http_version  1.0;
#     gzip_comp_level    2;
#     gzip_proxied       any;
#     gzip_types         text/plain text/css application/javascript text/xml application/xml+rss;
#     keepalive_timeout  65;
#     ssl_protocols      TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
#     ssl_ciphers        HIGH:!aNULL:!MD5;
#     client_max_body_size 80M;
#     server_tokens off;

#     absolute_redirect  off;
#     port_in_redirect   off;

# Ensure non-root user for OpenShift compatibility
# NGINX runs as 'nginx' user by default (UID 101).
# We ensure the logs and cache directories are writable.
RUN chown -R nginx:nginx /var/cache/nginx /var/run /var/log/nginx && \
    chmod -R 755 /var/cache/nginx /var/run /var/log/nginx

USER nginx

# Expose HTTP (and HTTPS if you terminate SSL at NGINX)
EXPOSE 8080 
EXPOSE 8081

CMD ["nginx", "-g", "daemon off;"]