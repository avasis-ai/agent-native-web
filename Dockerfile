FROM node:22-alpine
WORKDIR /app
COPY --chown=node:node package.json package-lock.json ./
COPY --chown=node:node src ./src
COPY --chown=node:node examples ./examples
RUN mkdir -p /app/data && chown node:node /app/data
USER node
ENV HOST=0.0.0.0 PORT=4317 AGENT_DATA_FILE=/app/data/state.json
EXPOSE 4317
HEALTHCHECK --interval=10s --timeout=2s --retries=3 CMD wget -q -O - http://127.0.0.1:4317/healthz >/dev/null || exit 1
CMD ["node", "src/server.mjs"]
