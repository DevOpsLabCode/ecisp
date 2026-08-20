# Build context is ui/frontend.
#   docker build -t golem-frontend --build-arg VITE_API_URL=http://localhost:8000 .
# Node >=22.22.2 -- see package.json's engines field (jsdom, a dev/test
# dependency, requires it; kept in sync here so the whole toolchain agrees).
FROM node:26-slim AS build
WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Vite bakes this in at build time (import.meta.env.VITE_API_URL), so it
# must match wherever the backend is actually reachable FROM THE BROWSER --
# not container-to-container networking, which the browser never sees.
ARG VITE_API_URL=http://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
RUN npm run build

FROM nginx:1.31-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
