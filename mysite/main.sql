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
);
