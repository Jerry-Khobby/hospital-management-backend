# Use Node.js 20.11.1 base image
FROM node:20.11.1-alpine

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install --legacy-peer-deps

# Copy Prisma schema and generate client (ONLY ONCE)
COPY prisma ./prisma/

# Copy the rest of the application code
COPY . .

# Expose the port
EXPOSE 3333

# Use a simple command that will be overridden by docker-compose
CMD ["npm", "run", "start:dev"]