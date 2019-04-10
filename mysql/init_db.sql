CREATE DATABASE IF NOT EXISTS `hello-mentors`;

USE `hello-mentors`;

CREATE TABLE `users`
(
  `id` INT PRIMARY KEY,
  `name` VARCHAR(255),
  `username` VARCHAR(255),
  `email` VARCHAR(255),
  `password` VARCHAR(255),
  `role` INT
);

CREATE TABLE `user_role`
(
  `id` INT PRIMARY KEY,
  `role` VARCHAR(255)
);

CREATE TABLE `tickets`
(
  `id` INT PRIMARY KEY,
  `hacker_id` INT NOT NULL,
  `mentor_id` INT,
  `submit_time` datetime NOT NULL,
  `location` VARCHAR(255) NOT NULL,
  `tags` SET('ANDROID', 'IOS', 'JAVA', 'JAVASCRIPT'),
  `message` VARCHAR(255) NOT NULL
);

ALTER TABLE `users` ADD FOREIGN KEY (`role`) REFERENCES `user_role` (`id`);

ALTER TABLE `tickets` ADD FOREIGN KEY (`hacker_id`) REFERENCES `users` (`id`);

ALTER TABLE `tickets` ADD FOREIGN KEY (`mentor_id`) REFERENCES `users` (`id`);