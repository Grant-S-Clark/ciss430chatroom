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

-- Add chat pictures later?
CREATE TABLE chats (
id     INT   AUTO_INCREMENT,
label  VARCHAR(200) NOT NULL,

PRIMARY KEY (id)
) engine=innodb;

-- Set up global chat by default, id for global is 1.
ALTER TABLE chats AUTO_INCREMENT = 1;
INSERT chats (label) VALUES ('Global Chat');

-- Access permissions for non-global chats.
CREATE TABLE chat_users (
chat_id      INT        NOT NULL,
user_id      INT        NOT NULL,

FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
FOREIGN KEY (user_id) REFERENCES chats(id) ON DELETE CASCADE
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
