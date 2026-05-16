# Use an official Node.js runtime as a parent image
FROM node:20-alpine
# Create app directory
WORKDIR /app
# Copy package.json and package-lock.json to the working directory
COPY package*.json ./
# Install app dependencies
RUN npm install
# Bundle app source
COPY . .
# make port 3000 available to the world outside this container
EXPOSE 3000
# start the application
CMD ["npm", "start"]