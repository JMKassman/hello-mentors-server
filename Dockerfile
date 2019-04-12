FROM node:10.13
ARG PORT=3000
ARG ENV=production
ENV NODE_ENV ${ENV}
WORKDIR /usr/src/app
COPY ["package.json", "package-lock.json*", "npm-shrinkwrap.json*", "./"]
RUN npm install
COPY . .
EXPOSE ${PORT}
CMD npm start