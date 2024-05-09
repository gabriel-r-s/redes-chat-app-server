-- users
INSERT INTO users(id, name, aes_key) VALUES(1, 'user1', '123');
INSERT INTO users(id, name, aes_key) VALUES(2, 'user2', '123');
INSERT INTO users(id, name, aes_key) VALUES(3, 'user3', '123');
INSERT INTO users(id, name, aes_key) VALUES(4, 'user4', '123');

-- rooms + admins
INSERT INTO rooms(id, name, private, pass, admin) VALUES(1, 'room1', FALSE, '', 1);
INSERT INTO rooms(id, name, private, pass, admin) VALUES(2, 'room2', FALSE, '', 2);
INSERT INTO rooms(id, name, private, pass, admin) VALUES(3, 'room3', FALSE, '', 3);
INSERT INTO rooms(id, name, private, pass, admin) VALUES(4, 'room4', FALSE, '', 4);

-- room users
INSERT INTO rel_room_user(user_id, room_id) VALUES(1, 2);
INSERT INTO rel_room_user(user_id, room_id) VALUES(1, 3);
INSERT INTO rel_room_user(user_id, room_id) VALUES(2, 1);
INSERT INTO rel_room_user(user_id, room_id) VALUES(2, 4);
INSERT INTO rel_room_user(user_id, room_id) VALUES(3, 1);
INSERT INTO rel_room_user(user_id, room_id) VALUES(3, 2);
INSERT INTO rel_room_user(user_id, room_id) VALUES(4, 1);
INSERT INTO rel_room_user(user_id, room_id) VALUES(4, 3);

-- some messages to send
INSERT INTO sent_msgs(id, msg) VALUES(1, 'usuario 1 é otario');
INSERT INTO sent_msgs(id, msg) VALUES(2, 'usuario 2 é otario');
INSERT INTO sent_msgs(id, msg) VALUES(3, 'usuario 3 é otario');
INSERT INTO sent_msgs(id, msg) VALUES(4, 'usuario 4 é otario');

-- who to send
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 1, 1, 2);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 2, 1, 3);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 3, 1, 4);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 4, 2, 1);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 5, 2, 3);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 6, 2, 4);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 7, 3, 1);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 8, 3, 2);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES( 9, 3, 4);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES(10, 4, 1);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES(11, 4, 2);
INSERT INTO rel_user_msg(id, user_id, msg_id) VALUES(12, 4, 3);


