FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --production 2>/dev/null || true
COPY index.js ./
EXPOSE 8080
CMD ["npm", "start"]
