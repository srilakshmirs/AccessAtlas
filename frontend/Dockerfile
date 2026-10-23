# Multi-stage Dockerfile for AccessAtlas Frontend

# Stage 1: Build static assets
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package*.json ./

# Install clean dependencies
RUN npm ci

# Copy application source
COPY . .

# Build production bundle
RUN npm run build

# Stage 2: Serve static assets via Nginx
FROM nginx:alpine

# Copy built distribution files from builder stage
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy custom Nginx configuration supporting SPA routing
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
