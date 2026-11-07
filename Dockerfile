FROM node:22-alpine
WORKDIR /app
COPY . .
ENV NODE_ENV=production DATA_DIR=/data PORT=3000
VOLUME /data
EXPOSE 3000
USER node
CMD ["node", "--no-warnings", "server/index.js"]
