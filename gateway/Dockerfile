FROM node:24-slim

WORKDIR /app

# Dev dependencies stay installed: tsx (which runs the TypeScript directly) is one of them.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src

# The image's built-in unprivileged user. The app only reads its files, so root can own them.
USER node
CMD ["node_modules/.bin/tsx", "src/index.ts"]
