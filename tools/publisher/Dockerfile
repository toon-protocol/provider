# The directory publisher (tools/publisher/README.md). Built from the provider
# repo root so the image is one `docker build -f tools/publisher/Dockerfile .`
# next to the provider's own.
FROM node:22-slim

WORKDIR /app
COPY tools/publisher/package.json tools/publisher/package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund

COPY tools/publisher/publish.mjs ./

# The channel store: the client's own watermark for the channel it pays on. A
# STALE one refuses every later claim, so it must outlive a restart and die
# with the chain.
RUN mkdir -p /var/lib/toon-publisher
VOLUME ["/var/lib/toon-publisher"]

ENV NODE_ENV=production
EXPOSE 8081

CMD ["node", "publish.mjs"]
