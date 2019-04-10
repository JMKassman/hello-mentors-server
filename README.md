# Hello Mentors Server

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
  2. Run `docker-compose up`
  3. Server is now running and mysql will use ./mysql-volume to store its data
 
### Teardown
  1. Run `docker-compose down`
  2. Docker containers will be stopped and deleted
  3. (Optional) Delete ./mysql-volume to remove the database
  
## Running the debug server
 - To be added later
