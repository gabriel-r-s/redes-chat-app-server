use sqlite::{ConnectionThreadSafe as Db, State};

const SQL_LOG_ENABLE: bool = true;

macro_rules! sqlite {
    ($db:expr, $sql:expr, $($arg:expr),* $(,)?) => {{
        if SQL_LOG_ENABLE {
            eprint!("query {{'");
            let mut _split = $sql.split_whitespace();
            if let Some(_s) = _split.next() {
                eprint!("{}", _s);
                for _s in _split {
                    eprint!(" {}", _s);
                }
            }
            $({
                eprint!(", {:?}", $arg);
            })*
            eprintln!("}}");
        }
        sqlite_no_log!($db, $sql, $($arg),*)
    }};
}

macro_rules! sqlite_no_log {
    ($db:expr, $sql:expr, $($arg:expr),* $(,)?) => {{
        let mut _query = $db.prepare($sql).unwrap();
        let mut _i = 1;
        $({
            _query.bind((_i, $arg)).unwrap();
            _i += 1;
        })*
        _query
    }};
}

#[derive(Clone)]
pub struct User {
    pub id: i64,
    pub name: String,
    pub aes_key: String,
}

impl User {
    pub fn create(db: &Db, name: &str) -> Option<i64> {
        let mut insert_user = sqlite!(
            db,
            "
            INSERT INTO users(name)
            VALUES(?)
            RETURNING id
            ",
            name,
        );
        if let State::Row = insert_user.next().unwrap() {
            Some(insert_user.read::<i64, _>("id").unwrap())
        } else {
            None
        }
    }

    pub fn delete_cascade(&self, db: &Db) {
        let mut delete_cascade = sqlite!(db, "DELETE FROM users WHERE id = ?", self.id);
        delete_cascade.next().unwrap();
    }

    pub fn get_id(db: &Db, name: &str) -> Option<i64> {
        let mut get_id = sqlite!(db, "SELECT id FROM users WHERE name = ?", name);
        if let State::Row = get_id.next().unwrap() {
            Some(get_id.read::<i64, _>("id").unwrap())
        } else {
            None
        }
    }

    pub fn send_to(db: &Db, user_id: i64, msg: &str) {
        let mut insert_message = sqlite!(
            db,
            "
            INSERT INTO messages (msg)
            VALUES(?)
            RETURNING id
            ",
            msg,
        );
        insert_message.next().unwrap();
        let msg_id = insert_message.read::<i64, _>("id").unwrap();

        let mut insert_rel_user_msg = sqlite!(
            db,
            "
            INSERT INTO rel_user_msg(user_id, msg_id)
            VALUES(?, ?)
            ",
            user_id,
            msg_id,
        );
        insert_rel_user_msg.next().unwrap();
    }

    pub fn drain_msgs(db: &'static Db, user_id: i64) -> Vec<String> {
        let mut get_msgs = sqlite_no_log!(
            db,
            "
            SELECT id, msg FROM view_user_msgs
            WHERE user_id = ?
            ",
            user_id,
        );

        let mut delete_rel = sqlite_no_log!(
            db,
            "
            DELETE FROM rel_user_msg
            WHERE id = ?;
            ",
        );

        let mut msgs = Vec::new();
        while let State::Row = get_msgs.next().unwrap() {
            let rel_id = get_msgs.read::<i64, _>(0).unwrap();
            let msg = get_msgs.read::<String, _>(1).unwrap();
            delete_rel.reset().unwrap();
            delete_rel.bind((1, rel_id)).unwrap();
            delete_rel.next().unwrap();
            msgs.push(msg);
        }
        msgs
    }
}

pub struct Room {
    pub id: i64,
    pub admin: i64,
}

impl Room {
    pub fn create(db: &Db, name: &str, private: bool, pass: &str, admin_id: i64) -> bool {
        let mut insert_room = sqlite!(
            db,
            "
            INSERT OR IGNORE INTO rooms(name, private, pass, admin)
            VALUES(?, ?, ?, ?)
            RETURNING (1)
            ",
            name,
            private as i64,
            pass,
            admin_id
        );
        insert_room.next().unwrap() == State::Row
    }

    pub fn get(db: &Db, name: &str) -> Option<Room> {
        let mut select_room = sqlite!(
            db,
            "
            SELECT id, admin FROM rooms
            WHERE name = ?
            ",
            name,
        );
        if let State::Row = select_room.next().unwrap() {
            let id = select_room.read::<i64, _>("id").unwrap();
            let admin = select_room.read::<i64, _>("admin").unwrap();
            Some(Room { id, admin })
        } else {
            None
        }
    }

    pub fn get_all(db: &'static Db) -> impl Iterator<Item = String> {
        let mut get_room_names = sqlite!(
            db,
            "
            SELECT name FROM rooms
            WHERE private = FALSE
            ",
        );

        std::iter::from_fn(move || {
            if get_room_names.next().unwrap() == State::Row {
                Some(get_room_names.read::<String, _>("name").unwrap())
            } else {
                None
            }
        })
    }

    pub fn get_all_from_member(
        db: &'static Db,
        user_id: i64,
    ) -> impl Iterator<Item = (Self, String)> {
        let mut get_ids = sqlite!(
            db,
            "
            SELECT room.id, room.admin, room.name FROM rel_room_user rel
            INNER JOIN rooms room ON room.id = rel.room_id AND room.admin != ?
            WHERE rel.user_id = ?
            ",
            user_id,
            user_id,
        );
        std::iter::from_fn(move || {
            if let Ok(State::Row) = get_ids.next() {
                let id = get_ids.read::<i64, _>("id").unwrap();
                let admin = get_ids.read::<i64, _>("admin").unwrap();
                let name = get_ids.read::<String, _>("name").unwrap();
                Some((Room { id, admin }, name))
            } else {
                None
            }
        })
    }
    pub fn get_all_from_admin(
        db: &'static Db,
        user_id: i64,
    ) -> impl Iterator<Item = (Room, String)> {
        let mut get_ids = sqlite!(
            db,
            "
            SELECT id, admin, name FROM rooms
            WHERE admin = ?
            ",
            user_id
        );
        std::iter::from_fn(move || {
            if let Ok(State::Row) = get_ids.next() {
                let id = get_ids.read::<i64, _>("id").unwrap();
                let admin = get_ids.read::<i64, _>("admin").unwrap();
                let name = get_ids.read::<String, _>("name").unwrap();
                Some((Room { id, admin }, name))
            } else {
                None
            }
        })
    }

    pub fn get_users(&self, db: &'static Db) -> impl Iterator<Item = String> {
        let mut get_user_names = sqlite!(
            db,
            "
            SELECT name FROM view_room_user_names
            WHERE room_id = ?
            ",
            self.id,
        );

        std::iter::from_fn(move || {
            if let Ok(State::Row) = get_user_names.next() {
                Some(get_user_names.read::<String, _>("name").unwrap())
            } else {
                None
            }
        })
    }

    pub fn is_member(&self, db: &Db, user_id: i64) -> bool {
        let mut get_member = sqlite!(
            db,
            "
            SELECT (1) FROM rel_room_user
            WHERE room_id = ? AND user_id = ?
            ",
            self.id,
            user_id,
        );
        get_member.next().unwrap() == State::Row
    }

    pub fn is_admin(&self, user_id: i64) -> bool {
        self.admin == user_id
    }

    pub fn is_banned(&self, db: &Db, user_id: i64) -> bool {
        let mut get_banned = sqlite!(
            db,
            "
            SELECT (1) FROM rel_room_banned
            WHERE room_id = ? AND user_id = ?
            ",
            self.id,
            user_id,
        );
        get_banned.next().unwrap() == State::Row
    }

    pub fn check_pass(&self, db: &Db, pass: &str) -> bool {
        let mut compare_pass = sqlite!(
            db,
            "
            SELECT (1) FROM rooms
            WHERE id = ? AND pass = ?
            ",
            self.id,
            pass,
        );
        compare_pass.next().unwrap() == State::Row
    }

    pub fn broadcast(&self, db: &Db, msg: &str, except0: i64, except1: i64) {
        let mut insert_message = sqlite!(
            db,
            "
            INSERT INTO messages(msg)
            VALUES(?)
            RETURNING id
            ",
            msg,
        );
        insert_message.next().unwrap();
        let msg_id = insert_message.read::<i64, _>("id").unwrap();

        let mut get_room_users = sqlite!(
            db,
            "
            SELECT user_id FROM rel_room_user
            WHERE room_id = ? AND user_id NOT IN (?, ?)
            ",
            self.id,
            except0,
            except1,
        );

        let mut insert_rel_user_msg = sqlite!(
            db,
            "
            INSERT INTO rel_user_msg(user_id, msg_id)
            VALUES(?, ?)
            ",
        );

        while let Ok(State::Row) = get_room_users.next() {
            let user_id = get_room_users.read::<i64, _>("user_id").unwrap();
            insert_rel_user_msg.reset().unwrap();
            insert_rel_user_msg.bind((1, user_id)).unwrap();
            insert_rel_user_msg.bind((2, msg_id)).unwrap();
            insert_rel_user_msg.next().unwrap();
        }
    }

    pub fn delete_cascade(&self, db: &Db) {
        let mut delete_cascade = sqlite!(
            db,
            "
            DELETE FROM rooms
            WHERE id = ?;
            ",
            self.id,
        );
        delete_cascade.next().unwrap();
    }

    pub fn add_user(&self, db: &Db, user_id: i64) {
        let mut insert_rel = sqlite!(
            db,
            "
            INSERT OR IGNORE INTO rel_room_user(room_id, user_id)
            VALUES(?, ?)
            ",
            self.id,
            user_id,
        );
        insert_rel.next().unwrap();
    }

    pub fn kick(&self, db: &Db, user_id: i64) -> bool {
        let mut delete_rel = sqlite!(
            db,
            "
            DELETE FROM rel_room_user
            WHERE room_id = ? AND user_id = ?
            RETURNING (1)
            ",
            self.id,
            user_id,
        );
        delete_rel.next().unwrap() == State::Row
    }

    pub fn ban(&self, db: &Db, user_id: i64) -> bool {
        let mut insert_rel = sqlite!(
            db,
            "
            INSERT OR IGNORE INTO rel_room_banned(room_id, user_id)
            VALUES(?, ?)
            RETURNING (1)
            ",
            self.id,
            user_id,
        );
        insert_rel.next().unwrap() == State::Row
    }
}
