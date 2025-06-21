FROM oven/bun:alpine
WORKDIR /auth-kit

COPY package.json .
COPY bun.lock .
RUN bun install --production

COPY . .

ENV NODE_ENV=production

USER bun
CMD ["bun", "start"]