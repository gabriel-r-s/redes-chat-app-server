PRAGMA foreign_keys = ON;

CREATE TABLE users(
    id          INTEGER PRIMARY KEY CHECK(id != 0),
    name        TEXT    NOT NULL
);

CREATE UNIQUE INDEX user_names ON users(name);

CREATE TABLE rooms(
    id      INTEGER PRIMARY KEY CHECK(id != 0),
    name    TEXT    NOT NULL,
    private BOOL    NOT NULL,
    pass    TEXT    NOT NULL,
    admin   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    CHECK(LENGTH(pass)=32 OR (private=FALSE AND LENGTH(pass)=0))
);

CREATE UNIQUE INDEX room_names ON rooms(name);

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

CREATE VIEW view_room_user_names AS
    SELECT rel.room_id, user.name FROM rel_room_user rel
    INNER JOIN users user ON user.id = rel.user_id;
    -- room_id, name

CREATE TABLE rel_room_banned(
    room_id INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(room_id, user_id)
);

CREATE TABLE messages(
    id      INTEGER PRIMARY KEY CHECK(id != 0),
    msg     TEXT    NOT NULL,
    CHECK(LENGTH(msg) != 0)
);

CREATE TABLE rel_user_msg(
    id      INTEGER PRIMARY KEY CHECK(id != 0),
    user_id INTEGER NOT NULL REFERENCES users(id)     ON DELETE CASCADE,
    msg_id  INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    UNIQUE(user_id, msg_id)
);

CREATE VIEW view_user_msgs AS
    SELECT rel.id, rel.user_id, msg.msg FROM rel_user_msg rel
    INNER JOIN messages msg ON msg.id = rel.msg_id;
    -- rel_id, user_id, msg


