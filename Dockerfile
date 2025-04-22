# Backend Dockerfile
FROM node:18

WORKDIR /app

COPY server/package*.json ./
RUN npm install

COPY server/ .

EXPOSE 4000

CMD ["node", "index.js"]
