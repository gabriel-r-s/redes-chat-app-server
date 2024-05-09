use sqlite::State;
type Db = sqlite::ConnectionThreadSafe;

pub struct User {
    pub id: i64,
    pub name: String,
    #[allow(dead_code)]
    pub aes_key: String,
}

impl User {
    pub fn delete_cascade(&self, db: &Db) {
        let mut delete_cascade = db
            .prepare(
                r#"
        DELETE FROM users
        WHERE id = ?;
            "#,
            )
            .unwrap();
        delete_cascade.bind((1, self.id)).unwrap();
        delete_cascade.next().unwrap();
    }

    pub fn get_id(db: &Db, name: &str) -> Option<i64> {
        let mut get_id = db
            .prepare(
                r#"
            SELECT id FROM users
            WHERE name = ?
            "#,
            )
            .unwrap();
        get_id.bind((1, name)).unwrap();
        if let State::Row = get_id.next().unwrap() {
            Some(get_id.read::<i64, _>("id").unwrap())
        } else {
            None
        }
    }

    pub fn send_to(db: &Db, user_id: i64, msg: &str) {
        let mut insert_message = db
            .prepare(
                r#"
            INSERT INTO sent_msgs (msg)
            VALUES(?)
            RETURNING id
            "#,
            )
            .unwrap();
        insert_message.bind((1, msg)).unwrap();
        insert_message.next().unwrap();
        let msg_id = insert_message.read::<i64, _>("id").unwrap();

        let mut insert_rel_user_msg = db
            .prepare(
                r#"
            INSERT INTO rel_user_msg(user_id, msg_id)
            VALUES(?, ?)
            "#,
            )
            .unwrap();
        insert_rel_user_msg.bind((1, user_id)).unwrap();
        insert_rel_user_msg.bind((2, msg_id)).unwrap();
        insert_rel_user_msg.next().unwrap();
    }

    pub fn drain_msgs(db: &'static Db, user_id: i64) -> impl Iterator<Item = String> {
        let mut get_msgs = db
            .prepare(
                r#"
            SELECT rel.id, msg.msg FROM rel_user_msg rel
            INNER JOIN sent_msgs msg ON msg.id = rel.msg_id
            WHERE rel.user_id = ?
            "#,
            )
            .unwrap();
        get_msgs.bind((1, user_id)).unwrap();

        let mut delete_rel = db
            .prepare(
                r#"
            DELETE FROM rel_user_msg
            WHERE id = ?;
            "#,
            )
            .unwrap();

        std::iter::from_fn(move || {
            if let State::Row = get_msgs.next().unwrap() {
                let rel_id = get_msgs.read::<i64, _>(0).unwrap();
                let msg = get_msgs.read::<String, _>(1).unwrap();
                delete_rel.reset().unwrap();
                delete_rel.bind((1, rel_id)).unwrap();
                delete_rel.next().unwrap();
                Some(msg)
            } else {
                None
            }
        })
    }
}

pub struct Room {
    pub id: i64,
    pub private: bool,
    pub admin: i64,
}

impl Room {
    pub fn create(db: &Db, name: &str, private: bool, pass: &str, admin_id: i64) -> bool {
        let mut insert_room = db
            .prepare(
                r#"
            INSERT OR IGNORE INTO rooms(name, private, pass, admin)
            VALUES(?, ?, ?)
            RETURNING (1)
            "#,
            )
            .unwrap();
        insert_room.bind((1, name)).unwrap();
        insert_room.bind((3, private as i64)).unwrap();
        insert_room.bind((3, pass)).unwrap();
        insert_room.bind((4, admin_id)).unwrap();
        insert_room.next().unwrap() == State::Row
    }

    pub fn get(db: &Db, name: &str) -> Option<Room> {
        let mut select_room = db
            .prepare(
                r#"
            SELECT id, private, admin FROM rooms
            WHERE name = ?
            "#,
            )
            .unwrap();
        select_room.bind((1, name)).unwrap();
        if let State::Row = select_room.next().unwrap() {
            let id = select_room.read::<i64, _>("id").unwrap();
            let private = select_room.read::<i64, _>("private").unwrap();
            let private = private != 0;
            let admin = select_room.read::<i64, _>("admin").unwrap();
            Some(Room { id, private, admin })
        } else {
            None
        }
    }

    pub fn get_all(db: &'static Db) -> impl Iterator<Item = String> {
        let mut get_room_names = db
            .prepare(
                r#"
            SELECT name FROM rooms
            WHERE private = FALSE
            "#,
            )
            .unwrap();

        std::iter::from_fn(move || {
            if let Ok(State::Row) = get_room_names.next() {
                Some(get_room_names.read::<String, _>("name").unwrap())
            } else {
                None
            }
        })
    }

    pub fn get_users(&self, db: &'static Db) -> impl Iterator<Item = String> {
        let mut get_user_names = db
            .prepare(
                r#"
            SELECT u.name FROM rel_room_user rel
            INNER JOIN users u ON rel.user_id = u.id
            WHERE rel.room_id = ?
            "#,
            )
            .unwrap();
        get_user_names.bind((1, self.id)).unwrap();

        std::iter::from_fn(move || {
            if let Ok(State::Row) = get_user_names.next() {
                Some(get_user_names.read::<String, _>(0).unwrap())
            } else {
                None
            }
        })
    }

    pub fn is_member(&self, db: &Db, user_id: i64) -> bool {
        let mut get_member = db
            .prepare(
                r#"
            SELECT (1) FROM rel_room_user
            WHERE room_id = ? AND user_id = ?
            "#,
            )
            .unwrap();
        get_member.bind((1, self.id)).unwrap();
        get_member.bind((2, user_id)).unwrap();
        get_member.next().unwrap() == State::Row
    }

    pub fn is_admin(&self, user_id: i64) -> bool {
        self.admin == user_id
    }

    pub fn is_banned(&self, db: &Db, user_id: i64) -> bool {
        let mut get_banned = db
            .prepare(
                r#"
            SELECT (1) FROM rel_room_banned
            WHERE room_id = ? AND user_id = ?
            "#,
            )
            .unwrap();
        get_banned.bind((1, self.id)).unwrap();
        get_banned.bind((2, user_id)).unwrap();
        get_banned.next().unwrap() == State::Row
    }

    pub fn check_pass(&self, db: &Db, pass: &str) -> bool {
        let mut compare_pass = db
            .prepare(
                r#"
            SELECT (1) FROM rooms
            WHERE id = ? AND pass = ?
            "#,
            )
            .unwrap();
        compare_pass.bind((1, self.id)).unwrap();
        compare_pass.bind((2, pass)).unwrap();
        compare_pass.next().unwrap() == State::Row
    }

    pub fn broadcast(&self, db: &Db, msg: &str, except0: i64, except1: i64) {
        let mut insert_message = db
            .prepare(
                r#"
            INSERT INTO sent_msgs(msg)
            VALUES(?)
            RETURNING id
            "#,
            )
            .unwrap();
        insert_message.bind((1, msg)).unwrap();
        insert_message.next().unwrap();
        let msg_id = insert_message.read::<i64, _>("id").unwrap();

        let mut get_room_users = db
            .prepare(
                r#"
            SELECT user_id FROM rel_room_user
            WHERE room_id = ? AND user_id NOT IN (?, ?)
            "#,
            )
            .unwrap();
        get_room_users.bind((1, self.id)).unwrap();
        get_room_users.bind((2, except0)).unwrap();
        get_room_users.bind((3, except1)).unwrap();

        let mut insert_rel_user_msg = db
            .prepare(
                r#"
            INSERT INTO rel_user_msg(user_id, msg_id)
            VALUES(?, ?)
            "#,
            )
            .unwrap();

        while let Ok(State::Row) = get_room_users.next() {
            let user_id = get_room_users.read::<i64, _>("user_id").unwrap();
            insert_rel_user_msg.reset().unwrap();
            insert_rel_user_msg.bind((1, user_id)).unwrap();
            insert_rel_user_msg.bind((2, msg_id)).unwrap();
            insert_rel_user_msg.next().unwrap();
        }
    }

    pub fn delete_cascade(&self, db: &Db) {
        let mut delete_cascade = db
            .prepare(
                r#"
            DELETE FROM rooms
            WHERE id = ?;
            "#,
            )
            .unwrap();
        delete_cascade.bind((1, self.id)).unwrap();
        delete_cascade.next().unwrap();
    }

    pub fn add_user(&self, db: &Db, user_id: i64) {
        let mut insert_rel = db
            .prepare(
                r#"
            INSERT OR IGNORE INTO rel_room_user(room_id, user_id)
            VALUES(?, ?)
            "#,
            )
            .unwrap();
        insert_rel.bind((1, self.id)).unwrap();
        insert_rel.bind((2, user_id)).unwrap();
    }

    pub fn kick(&self, db: &Db, user_id: i64) -> bool {
        let mut delete_rel = db
            .prepare(
                r#"
            DELETE FROM rel_room_user
            WHERE room_id = ? AND user_id = ?
            "#,
            )
            .unwrap();
        delete_rel.bind((1, self.id)).unwrap();
        delete_rel.bind((2, user_id)).unwrap();
        delete_rel.next().unwrap() == State::Row
    }

    pub fn ban(&self, db: &Db, user_id: i64) -> bool {
        let mut insert_rel = db
            .prepare(
                r#"
            INSERT OR IGNORE INTO rel_room_banned(room_id, user_id)
            VALUES(?, ?)
            "#,
            )
            .unwrap();
        insert_rel.bind((1, self.id)).unwrap();
        insert_rel.bind((2, user_id)).unwrap();
        insert_rel.next().unwrap() == State::Row
    }
}
