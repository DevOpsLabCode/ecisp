# Build context is ui/frontend.
#   docker build -t ecisp-frontend --build-arg VITE_API_URL=http://localhost:8000 .
FROM node:20-slim AS build
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

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
