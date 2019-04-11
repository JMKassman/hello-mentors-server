CREATE DATABASE IF NOT EXISTS `hello-mentors`;

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