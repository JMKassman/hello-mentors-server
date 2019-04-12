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
  `role` ENUM('Hacker', 'Mentor', 'Coordinator')
);

CREATE TABLE `tickets`
(
  `id` INT PRIMARY KEY AUTO_INCREMENT,
  `hacker_id` INT NOT NULL,
  `mentor_id` INT,
  `submit_time` datetime NOT NULL,
  `status` ENUM('Open', 'Claimed', 'Complete'),
  `location` VARCHAR(255) NOT NULL,
  `tags` SET('ANDROID', 'IOS', 'JAVA', 'JAVASCRIPT'),
  `message` VARCHAR(255) NOT NULL
);

ALTER TABLE `tickets` ADD FOREIGN KEY (`hacker_id`) REFERENCES `users` (`id`);

ALTER TABLE `tickets` ADD FOREIGN KEY (`mentor_id`) REFERENCES `users` (`id`);

-- users are jkass:asdf vtat:qwer crose:zxcv
INSERT INTO users (name, username, email, password, role) 
VALUES("josh", "jkass", "jkass@example.com", "$2b$10$LjlSBAAWIN4WPRWwKgK9OOmaZrD87iNiD4NeuVtRYaPcznj.eyhYC", 'Hacker'),
("vikas", "vtati", "vtat@example.com", "$2b$10$/bs0zsZ/RVYItcskIb9m0O7qjc.BFOw2fs5yPwFhiH.2NUl2ss3si", 'Mentor'),
("chris", "crose", "crose@example.com", "$2b$10$0tCQV/l1oTRbRl5lCi5gOOsvF/XelBA1yBFvChbsOz1OKLOKA7oc6", 'Coordinator');

INSERT INTO tickets (hacker_id, submit_time, status, location, tags, message) 
VALUES((SELECT id FROM users WHERE email="jkass@example.com"), "2019-04-11 10:15:34", "Open", "880b", '', "Please Help ASAP");

INSERT INTO tickets (hacker_id, mentor_id, submit_time, status, location, tags, message)
VALUES((SELECT id FROM users WHERE email="jkass@example.com"), (SELECT id FROM users WHERE email="vtat@example.com"), "2019-04-11 10:05:24", "Claimed", "Lawson", 'ANDROID', "Android studio wont work");

INSERT INTO tickets (hacker_id, mentor_id, submit_time, status, location, tags, message) 
VALUES((SELECT id FROM users WHERE email="jkass@example.com"), (SELECT id FROM users WHERE email="vtat@example.com"), "2019-04-10 10:05:24", "Complete", "Lawson", 'JAVA,ANDROID', "Android studio R not resolving");