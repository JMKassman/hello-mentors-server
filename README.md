# Hello Mentors Server 
[![Build Status](https://travis-ci.org/JMKassman/hello-mentors-server.svg?branch=master)](https://travis-ci.org/JMKassman/hello-mentors-server)

Server for [Hello Mentors](https://github.com/crosenblatt/hello-mentors)

## Running the server without docker

### Requirements
 - node
 - npm
 - mysql

### Setup
  1. Copy .env.template to .env and populate the variables
  2. Run ./mysql/init_db.sql on your mysql instance
  3. Run `npm install`
  4. Run `npm start`
  5. Server is now running
  
## Running the server with docker

### Requirements
  - docker
  - docker-compose
  
### Setup
  1. Copy .env.template to .env and populate the variables
  2. Run `docker-compose -f "docker-compose.yml" up -d --build`
  3. Server is now running and mysql will use ./mysql-volume to store its data
 
### Teardown
  1. Run `docker-compose -f "docker-compose.yml" down`
  2. Docker containers will be stopped and deleted
  3. (Optional) Delete ./mysql-volume to remove the database
  
## Running the debug server in docker

### Requirements
  - docker
  - docker-compose

### Setup
  1. Copy .env.template to .env and populate the variables
  2. Run `docker-compose -f "docker-compose.debug.yml" up -d --build`
  3. Server is now running and mysql will use ./mysql-volume to store its data

### Features not in default server
  - Database is prepopulated with sample data
  - node --inspect available at port 9229 for attaching a debugger
  - adminer running on port 8080 for database inspection

### Teardown
  1. Run `docker-compose -f "docker-compose.debug.yml" down`
  2. Docker containers will be stopped and deleted
  3. (Optional) Delete ./mysql-volume to remove the database
