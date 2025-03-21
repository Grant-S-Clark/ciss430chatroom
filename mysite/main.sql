-- LOCAL
DROP DATABASE IF EXISTS ciss430chatroom;
CREATE DATABASE ciss430chatroom;
USE ciss430chatroom;

/*
-- PYTHONANYWHERE
DROP DATABASE IF EXISTS ciss430chatroom$default;
CREATE DATABASE ciss430chatroom$default;
USE ciss430chatroom$default;
*/

CREATE TABLE users (
id           INT                AUTO_INCREMENT,
email        VARCHAR(200)       NOT NULL, -- for verification later
username     VARCHAR(100)       NOT NULL,
salt         CHAR(24)           NOT NULL,
hpassword    CHAR(64)           NOT NULL, -- sha256 = 64 chars
PRIMARY KEY (id),
KEY (username)
) engine=innodb;

-- TEST USERS, DELETE LATER
INSERT INTO users (email, username, salt, hpassword) VALUES
('test@gmail.com', 'test', 'S4k=?lCCtmV~)gM]y\\-vHHV"', '69dbe8097d772c70139e7385875bd7f75775b852d41cf6a08ea43b586d6df9a8'),
('test@gmail.com', 'test2', 'aIh9.sI^[--g.q4qFSg2A7sv', 'f7776285e22963da2563dc60a943187ce4c67b7082541fddccd3e7adc86027f2'),
('test@gmail.com', 'test3', 'Q^N=m>k@~7pz`i]u2@ZFB[Z3', '187253f179ef370f01a723d2b2a78cd5260994b490ce16a187df886fe958ffdd');

-- Add chat pictures later?
CREATE TABLE chats (
id           INT                           AUTO_INCREMENT,
label        VARCHAR(200), -- DM labels determined based on user viewing it, so NULL
chat_type    ENUM('GLOBAL', 'DM', 'GROUP') NOT NULL,

PRIMARY KEY (id)
) engine=innodb;

-- Set up global chat by default, id for global is 1.
ALTER TABLE chats AUTO_INCREMENT = 1;
INSERT chats (label, chat_type) VALUES ('Global Chat', 'GLOBAL');

-- Access permissions for non-global chats.
CREATE TABLE chat_users (
chat_id      INT        NOT NULL,
user_id      INT        NOT NULL,
time_joined  TIMESTAMP  DEFAULT CURRENT_TIMESTAMP,

FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) engine=innodb;

-- Maybe bigint for id so we dont overflow the id count with a
-- huge number of messages?
CREATE TABLE messages (
id     INT   AUTO_INCREMENT,
user_id      INT,      -- NULL will mean a system message later on.
chat_id      INT       NOT NULL,
message      TEXT      NOT NULL,  -- Allow null later for messages with
                                  -- no text but have a file
time_sent    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

PRIMARY KEY (id),
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE
) engine=innodb;
