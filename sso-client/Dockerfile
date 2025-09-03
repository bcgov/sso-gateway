# Stage 1: Build the Node.js application
# Use a Node.js image that includes npm and build tools
FROM node:20-alpine AS builder

# Set working directory inside the container
RUN mkdir -p /app
WORKDIR /app

COPY . /app
RUN npm install && npm run compile

# Stage 2: Create the final production image
# Use a slimmed-down Node.js image for production.
# It should match the Node.js version of the builder for consistency
FROM node:20-alpine

# Set working directory inside the container
WORKDIR /app

# Ensure non-root user for OpenShift compatibility
# The 'node' user exists by default in official Node.js images
# and usually has UID 1000. OpenShift will run with an arbitrary UID.
# We ensure the /app directory is owned by the 'node' user.
RUN chown -R node:node /app
USER node

# Copy only the necessary files from the builder stage
# This keeps the final image small and secure
# 1. node_modules (installed in builder stage)
# 2. Compiled JavaScript files from 'dist'
# 3. package.json (needed for 'npm start' to find the main script)
# 4. config.js (the compiled version of config.ts)
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./package.json

# DEBUG 5: List contents in the final stage after copying 'dist'
RUN echo "--- DEBUG 5: In final stage, after copying dist ---" && ls -la /app/dist/
RUN echo "--- DEBUG 5b: List contents of /app/ in final stage ---" && ls -la /app/


# Expose the port your Node.js app listens on
EXPOSE 3000

# Command to run the application
# This will execute 'node dist/index.js' as defined in your package.json's "start" script
CMD ["npm", "start"]