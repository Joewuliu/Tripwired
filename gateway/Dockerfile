FROM node:24-slim

WORKDIR /app

# Dev dependencies stay installed: tsx (which runs the TypeScript directly) is one of them.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

# Family links are kept in /app/data (a volume in docker-compose.yml), owned by the unprivileged
# user the app runs as. The app only reads its other files, so root can own those.
RUN mkdir -p /app/data && chown node:node /app/data && chmod 700 /app/data
ENV TRIPWIRE_DATA_DIR=/app/data
USER node
CMD ["node_modules/.bin/tsx", "src/index.ts"]
