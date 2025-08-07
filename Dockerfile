FROM oven/bun:alpine
WORKDIR /auth-kit

ENV DOCKERIZE_VERSION=v0.9.5

RUN apk update --no-cache \
    && apk add --no-cache wget openssl \
    && wget -O - "https://github.com/jwilder/dockerize/releases/download/$DOCKERIZE_VERSION/dockerize-alpine-linux-amd64-$DOCKERIZE_VERSION.tar.gz" | tar xzf - -C /usr/local/bin \
    && apk del wget

COPY tsconfig.json .
COPY package.json .
COPY bun.lock .
RUN bun install --production

COPY ./src ./src

ENV NODE_ENV=production

USER bun
CMD ["dockerize", "-wait", "tcp://db:3306", "-timeout", "10s", "bun", "start"]