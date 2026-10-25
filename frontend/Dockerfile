# syntax=docker/dockerfile:1
FROM node:20-alpine AS builder

ARG VITE_API_BASE_URL=http://localhost:8080
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

WORKDIR /src
COPY package.json ./
RUN npm install --legacy-peer-deps

COPY . .
RUN npx vite build

FROM nginx:1.27-alpine

COPY --from=builder /src/www /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:80/ || exit 1
