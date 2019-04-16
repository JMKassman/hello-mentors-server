CREATE DATABASE IF NOT EXISTS `hello-mentors`;

CREATE DATABASE IF NOT EXISTS `sessions`;

GRANT ALL PRIVILEGES ON sessions.* TO dbuser;

USE `hello-mentors`;

CREATE TABLE `users`
(
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `name` VARCHAR(255),
  `email` VARCHAR(255),
  UNIQUE KEY unique_email(email),
  `password` VARCHAR(255),
  `role` ENUM('Hacker', 'Mentor', 'Organizer'),
  `password_reset_token` VARCHAR(255) NULL,
  `password_reset_token_expiration` datetime NULL
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

-- users are jkassman@purdue.edu:asdf vtatinen@purdue.edu:qwer rosenblc@purdue.edu:zxcv
INSERT INTO users (name, email, password, role) 
VALUES("josh", "jkassman@purdue.edu", "$2b$10$LjlSBAAWIN4WPRWwKgK9OOmaZrD87iNiD4NeuVtRYaPcznj.eyhYC", 'Hacker'),
("vikas", "vtatinen@purdue.edu", "$2b$10$glzKke.feNFNLAbXTB67gOKaEGRQG5mXwKVEiRVb3JCH8tHqT/7T2", 'Mentor'),
("chris", "rosenblc@purdue.edu", "$2b$10$0tCQV/l1oTRbRl5lCi5gOOsvF/XelBA1yBFvChbsOz1OKLOKA7oc6", 'Organizer');

INSERT INTO mentors (mentor_id, skills, status)
VALUES((SELECT id FROM users WHERE email="vtatinen@purdue.edu"), 'lol no', 'OUT');

INSERT INTO tickets (hacker_id, submit_time, status, location, tags, message) 
VALUES((SELECT id FROM users WHERE email="jkassman@purdue.edu"), "2019-04-11 10:15:34", "Open", "880b", 'IOS', "Please Help ASAP");

INSERT INTO tickets (hacker_id, mentor_id, submit_time, status, location, tags, message)
VALUES((SELECT id FROM users WHERE email="jkassman@purdue.edu"), (SELECT id FROM users WHERE email="vtatinen@purdue.edu"), "2019-04-11 10:05:24", "Claimed", "Lawson", 'ANDROID', "Android studio wont work");

INSERT INTO tickets (hacker_id, mentor_id, submit_time, status, location, tags, message) 
VALUES((SELECT id FROM users WHERE email="jkassman@purdue.edu"), (SELECT id FROM users WHERE email="vtatinen@purdue.edu"), "2019-04-10 10:05:24", "Closed", "Lawson", 'JAVA,ANDROID', "Android studio R not resolving");

DELIMITER //
CREATE PROCEDURE insert_mentor (IN mentor_name VARCHAR(255), IN mentor_email VARCHAR(255), IN mentor_skills VARCHAR(255))
BEGIN
INSERT INTO users (name, email, role) VALUES(mentor_name, mentor_email, 'MENTOR');
INSERT INTO mentors (mentor_id, skills, status) VALUES((SELECT id FROM users WHERE email = mentor_email), mentor_skills, 'Out');
END//
DELIMITER ;