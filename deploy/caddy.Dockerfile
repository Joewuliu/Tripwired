# Caddy with the built report site inside it. Built from the repository root (docker-compose.yml
# sets the context), so the web app is compiled on the VM and nothing has to be built by hand.
FROM node:24-alpine AS web
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM caddy:2-alpine
COPY --from=web /web/dist /srv/web
