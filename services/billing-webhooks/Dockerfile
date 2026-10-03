# syntax=docker/dockerfile:1
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
ENV NODE_ENV=production PORT=8081
WORKDIR /app
COPY --from=build --chown=root:root /app/node_modules ./node_modules
COPY --from=build --chown=root:root /app/dist ./dist
COPY package.json ./
# Mount Apple's root at this path (see README); it is public, so baking it in is also fine.
ENV APPLE_ROOT_CA_PATH=/etc/slipstream/AppleRootCA-G3.cer
USER node
EXPOSE 8081
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s \
  CMD node -e "fetch('http://127.0.0.1:'+process.env.PORT+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
# exec form: node is PID 1 and receives SIGTERM for graceful shutdown
CMD ["node", "dist/main.js"]
