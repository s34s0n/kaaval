# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Kaaval dashboard — multi-stage: Vite production build served by nginx.
# nginx serves the static SPA and reverse-proxies /api and /ws to the backend, so
# the browser talks to a single same-origin host (no CORS, no dev server in prod).
#   build context is ./frontend
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . ./
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
