FROM node:22-slim
WORKDIR /app
COPY package.json server.js ./
ENV DATA_DIR=/data PORT=8788
VOLUME /data
EXPOSE 8788
CMD ["node", "--no-warnings", "server.js"]
