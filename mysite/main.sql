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

-- temporary, later make this more fleshed out, add file upload,
-- images, allow for DMs, allow for group chats, etc...
-- Maybe make a messages table? Would need to make the id into a
-- bigint though to make sure we dont overflow the id count.
CREATE TABLE global_chat (
id           INT         AUTO_INCREMENT,
user_id      INT         NOT NULL,
message      TEXT        NOT NULL,
time_sent    TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,

PRIMARY KEY (id),
FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) engine=innodb;
