CREATE DATABASE IF NOT EXISTS `hello-mentors`;

CREATE DATABASE IF NOT EXISTS `sessions`;

GRANT ALL PRIVILEGES ON sessions.* TO dbuser;

USE `hello-mentors`;

CREATE TABLE `users`
(
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `name` VARCHAR(255),
  `username` VARCHAR(255),
  `email` VARCHAR(255),
  `password` VARCHAR(255),
  `role` ENUM('Hacker', 'Mentor', 'Organizer')
);

CREATE TABLE `tickets`
(
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `hacker_id` INT NOT NULL,
  `mentor_id` INT,
  `submit_time` datetime NOT NULL,
  `status` ENUM('Open', 'Claimed', 'Closed'),
  `location` VARCHAR(255) NOT NULL,
  `tags` SET('ANDROID', 'IOS', 'JAVA', 'JAVASCRIPT'),
  `message` VARCHAR(255) NOT NULL
);

CREATE TABLE `mentors`
(
  `mentor_id` INT NOT NULL,
  `skills` VARCHAR(255) NOT NULL,
  `status` ENUM('In', 'Out'),
  `start_time` datetime NULL,
  `end_time` datetime NULL,
  `total_time` time NULL
);

ALTER TABLE `tickets` ADD FOREIGN KEY (`hacker_id`) REFERENCES `users` (`id`);

ALTER TABLE `tickets` ADD FOREIGN KEY (`mentor_id`) REFERENCES `users` (`id`);

ALTER TABLE `mentors` ADD FOREIGN KEY (`mentor_id`) REFERENCES `users` (`id`);

-- users are jkass:asdf vtati:qwer crose:zxcv
INSERT INTO users (name, username, email, password, role) 
VALUES("josh", "jkass", "jkass@example.com", "$2b$10$LjlSBAAWIN4WPRWwKgK9OOmaZrD87iNiD4NeuVtRYaPcznj.eyhYC", 'Hacker'),
("vikas", "vtati", "vtat@example.com", "$2b$10$glzKke.feNFNLAbXTB67gOKaEGRQG5mXwKVEiRVb3JCH8tHqT/7T2", 'Mentor'),
("chris", "crose", "crose@example.com", "$2b$10$0tCQV/l1oTRbRl5lCi5gOOsvF/XelBA1yBFvChbsOz1OKLOKA7oc6", 'Organizer');

INSERT INTO mentors (mentor_id, skills, status)
VALUES((SELECT id FROM users WHERE email="vtat@example.com"), 'lol no', 'OUT');

INSERT INTO tickets (hacker_id, submit_time, status, location, tags, message) 
VALUES((SELECT id FROM users WHERE email="jkass@example.com"), "2019-04-11 10:15:34", "Open", "880b", '', "Please Help ASAP");

INSERT INTO tickets (hacker_id, mentor_id, submit_time, status, location, tags, message)
VALUES((SELECT id FROM users WHERE email="jkass@example.com"), (SELECT id FROM users WHERE email="vtat@example.com"), "2019-04-11 10:05:24", "Claimed", "Lawson", 'ANDROID', "Android studio wont work");

INSERT INTO tickets (hacker_id, mentor_id, submit_time, status, location, tags, message) 
VALUES((SELECT id FROM users WHERE email="jkass@example.com"), (SELECT id FROM users WHERE email="vtat@example.com"), "2019-04-10 10:05:24", "Closed", "Lawson", 'JAVA,ANDROID', "Android studio R not resolving");