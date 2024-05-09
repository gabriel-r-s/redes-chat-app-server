PRAGMA foreign_keys = ON;

CREATE TABLE users(
    id          INTEGER PRIMARY KEY CHECK(id != 0),
    name        TEXT    NOT NULL UNIQUE,
    aes_key     TEXT    NOT NULL
);

CREATE TABLE rooms(
    id      INTEGER PRIMARY KEY,
    name    TEXT    NOT NULL UNIQUE CHECK(id != 0),
    private BOOL    NOT NULL,
    pass    TEXT    NOT NULL,
    admin   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    CHECK(LENGTH(pass)=32 OR (private=FALSE AND LENGTH(pass)=0))
);

CREATE TABLE rel_room_user(
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(room_id, user_id)
); 

CREATE TRIGGER admin_also_member
    AFTER INSERT ON rooms
BEGIN
    INSERT INTO rel_room_user(room_id, user_id)
        VALUES(NEW.id, NEW.admin);
END;

CREATE TABLE rel_room_banned(
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(room_id, user_id)
);

CREATE TABLE sent_msgs(
    id      INTEGER PRIMARY KEY CHECK(id != 0),
    msg     TEXT    NOT NULL,
    CHECK(LENGTH(msg) != 0)
);

CREATE TABLE rel_user_msg(
    id      INTEGER PRIMARY KEY CHECK(id != 0),
    user_id INTEGER NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
    msg_id  INTEGER NOT NULL REFERENCES sent_msgs(id) ON DELETE CASCADE,
    UNIQUE(user_id, msg_id)
);

