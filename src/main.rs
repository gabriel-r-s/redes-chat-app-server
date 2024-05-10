use async_std::io::BufReader;
use async_std::net::{SocketAddr, TcpListener, TcpStream};
use async_std::prelude::*;
use async_std::task;
use rsa::RsaPrivateKey;
use sqlite::{ConnectionThreadSafe, State};
use std::fmt::Write as _;
use std::time::Duration;

mod parse;
use parse::Command;
mod data;
use data::*;

const READ_TIMEOUT: Duration = Duration::from_millis(500);

async fn auth_client(
    db: &ConnectionThreadSafe,
    stream: &mut BufReader<TcpStream>,
    rsa_key: &RsaPrivateKey,
    buf: &mut String,
) -> Option<User> {
    /*
     * REGISTRO usuario             .. REGISTRO_OK
     * AUTENTICACAO usuario         .. CHAVE_PUBLICA rsa_key
     * CHAVE_SIMETRICA RSA(aes_key) ..
     * AES(comandos ...)            .. AES(respostas ...)
     */

    // registro
    buf.clear();
    task::block_on(stream.read_line(buf)).ok()?;
    let name = parse::command_register(&buf)?.to_string();
    // check if there is a user with name
    let mut stmt = db
        .prepare(
            "
        SELECT 1 FROM users WHERE name = ?",
        )
        .unwrap();
    stmt.bind((1, name.as_str())).unwrap();
    if let Ok(State::Row) = stmt.next() {
        let _ = task::block_on(writeln!(
            stream.get_mut(),
            "ERRO usuário '{}' já existe",
            name
        ));
        return None;
    }
    task::block_on(writeln!(stream.get_mut(), "REGISTRO_OK")).ok()?;

    // autenticação RSA
    buf.clear();
    task::block_on(stream.read_line(buf)).ok()?;
    if parse::command_auth(&buf) != Some(name.as_str()) {
        let _ = task::block_on(writeln!(stream.get_mut(), "ERRO nome de usuário difere"));
        return None;
    }
    let rsa_pub = rsa::RsaPublicKey::from(rsa_key);
    task::block_on(writeln!(stream.get_mut(), "CHAVE_PUBLICA {:?}", rsa_pub)).ok()?;

    // transmissão chave simétrica
    buf.clear();
    task::block_on(stream.read_line(buf)).ok()?;
    let aes_key = if let Some(_aes_key) = parse::command_aes_key(&buf) {
        // rsa_decode(rsa_pri, base64_decode(aes_key))
        "aes_key_goes_here".to_string()
    } else {
        let _ = task::block_on(writeln!(
            stream.get_mut(),
            "ERRO transmissao de chave simetrica"
        ));
        return None;
    };

    // inserir usuário e retornar id
    let mut insert_get_id = db
        .prepare(
            r#"
         INSERT INTO users (name, aes_key) 
         VALUES (?, ?)
         RETURNING id
        "#,
        )
        .unwrap();
    insert_get_id.bind((1, name.as_str())).unwrap();
    insert_get_id.bind((2, aes_key.as_str())).unwrap();
    let _ = insert_get_id.next();
    let id = insert_get_id.read::<i64, _>(0).unwrap();
    Some(User { id, name, aes_key })
}

async fn handle_client(
    db: &'static ConnectionThreadSafe,
    mut stream: BufReader<TcpStream>,
    rsa_key: &RsaPrivateKey,
) {
    let mut buf = String::new();
    let mut msg = String::new();
    // TODO dev only!!!!
    let user = User {
        id: 1,
        name: "admin12_user123".to_string(),
        aes_key: "123".to_string(),
    };
    // let Some(user) = auth_client(&db, &mut stream, rsa_key, &mut buf).await else {
    //     let _ = writeln!(stream.get_mut(), "ERRO de autenticacao").await;
    //     return;
    // };
    buf.clear();
    let mut closed = false;
    'run: while !closed {
        for msg in User::drain_msgs(db, user.id) {
            if task::block_on(writeln!(stream.get_mut(), "{}", msg)).is_err() {
                break 'run;
            }
        }
        match async_std::future::timeout(READ_TIMEOUT, stream.read_line(&mut buf)).await {
            Ok(Ok(1..)) => { /* ok :) */ }
            Ok(Ok(0) | Err(_)) => break 'run,
            Err(_) => continue,
        }

        // TODO AES encrypt/decrypt

        match parse::command(&buf) {
            Some(Command::ListRooms) => {
                msg.clear();
                let _ = write!(&mut msg, "SALAS");
                for room_name in Room::get_all(db) {
                    let _ = write!(&mut msg, " {}", room_name);
                }
                // TODO AES encrypt/decrypt
                closed |= task::block_on(writeln!(stream.get_mut(), "{}", msg)).is_err();
            }
            Some(Command::LeaveRoom { room_name }) => {
                let Some(room) = Room::get(db, room_name) else {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala '{}' não encontrada",
                        room_name
                    ))
                    .is_err();
                    continue;
                };
                if !room.is_member(db, user.id) {
                    closed |=
                        task::block_on(writeln!(stream.get_mut(), "ERRO não é membro da sala"))
                            .is_err();
                    continue;
                }
                if room.is_admin(user.id) {
                    closed |=
                        task::block_on(writeln!(stream.get_mut(), "ERRO admin deve fechar a sala"))
                            .is_err();
                    continue;
                }
                room.kick(db, user.id);
                msg.clear();
                let _ = write!(&mut msg, "SAIU {}", user.name);
                room.broadcast(db, &msg, user.id, 0);
            }
            Some(Command::CloseRoom { room_name }) => {
                let Some(room) = Room::get(db, room_name) else {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala '{}' não encontrada",
                        room_name
                    ))
                    .is_err();
                    continue;
                };
                if !room.is_admin(user.id) {
                    closed |=
                        task::block_on(writeln!(stream.get_mut(), "ERRO não é admin")).is_err();
                    continue;
                }
                msg.clear();
                let _ = write!(&mut msg, "SALA_FECHADA {}", room_name);
                room.broadcast(db, &msg, user.id, 0);
                room.delete_cascade(db);
                closed |= task::block_on(writeln!(stream.get_mut(), "FECHAR_SALA_OK")).is_err();
            }
            Some(Command::CreateRoom {
                room_name,
                private,
                pass,
            }) => {
                if Room::get(db, room_name).is_some() {}
                // TODO decode base64
                // NOTE maybe check length of pass hash SHA-256 = 32B
                if private && pass.is_empty() {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala privada deve ter uma senha"
                    ))
                    .is_err();
                    continue;
                }
                if Room::create(db, room_name, private, pass, user.id) {
                    closed |= task::block_on(writeln!(stream.get_mut(), "CRIAR_SALA_OK")).is_err();
                } else {
                    closed |=
                        task::block_on(writeln!(stream.get_mut(), "ERRO sala ja existe")).is_err();
                    continue;
                }
            }
            Some(Command::JoinRoom { room_name, pass }) => {
                let Some(room) = Room::get(db, room_name) else {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala '{}' não encontrada",
                        room_name
                    ))
                    .is_err();
                    continue;
                };
                if room.is_banned(db, user.id) {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO banido da sala '{}'",
                        room_name
                    ))
                    .is_err();
                    continue;
                }
                if room.is_member(db, user.id) {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO já está na sala '{}'",
                        room_name
                    ))
                    .is_err();
                    continue;
                }
                // TODO decode base64
                if !room.check_pass(db, pass) {
                    closed |=
                        task::block_on(writeln!(stream.get_mut(), "ERRO senha incorreta")).is_err();
                    continue;
                }
                room.add_user(db, user.id);

                msg.clear();
                let _ = write!(&mut msg, "ENTROU {} {}", room_name, user.name);
                room.broadcast(db, &msg, user.id, 0);

                msg.clear();
                let _ = write!(&mut msg, "ENTRAR_SALA_OK");
                for user_name in room.get_users(db) {
                    let _ = write!(&mut msg, " {}", user_name);
                }
                closed |= task::block_on(writeln!(stream.get_mut(), "{}", msg)).is_err();
            }
            Some(Command::SendMsg {
                room_name,
                sent_msg,
            }) => {
                let Some(room) = Room::get(db, room_name) else {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala '{}' não encontrada",
                        room_name
                    ))
                    .is_err();
                    continue;
                };
                if !room.is_member(db, user.id) {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala '{}' não encontrada",
                        room_name
                    ))
                    .is_err();
                    continue;
                }
                msg.clear();
                let _ = write!(
                    &mut msg,
                    "MENSAGEM {} {} {}",
                    room_name, user.name, sent_msg
                );
                room.broadcast(db, &msg, user.id, 0);
            }
            Some(Command::BanUser {
                room_name,
                banned_name,
            }) => {
                let Some(room) = Room::get(db, room_name) else {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO sala '{}' não encontrada",
                        room_name
                    ))
                    .is_err();
                    continue;
                };
                if !room.is_admin(user.id) {
                    closed |=
                        task::block_on(writeln!(stream.get_mut(), "ERRO não é admin")).is_err();
                    continue;
                }
                let Some(banned_id) = User::get_id(db, banned_name) else {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO usuário '{}' não encontrado",
                        banned_name
                    ))
                    .is_err();
                    continue;
                };
                if banned_id == user.id {
                    closed |= task::block_on(writeln!(
                        stream.get_mut(),
                        "ERRO não pode banir a si mesmo"
                    ))
                    .is_err();
                    continue;
                }
                if room.kick(db, banned_id) {
                    msg.clear();
                    let _ = write!(&mut msg, "SAIU {} {}", room_name, banned_name);
                    room.broadcast(db, &msg, user.id, banned_id);
                }
                if room.ban(db, banned_id) {
                    msg.clear();
                    let _ = write!(&mut msg, "BANIDO_DA_SALA {}", room_name);
                    User::send_to(db, banned_id, &msg);
                }
                closed |= task::block_on(writeln!(stream.get_mut(), "BANIMENTO_OK")).is_err();
            }
            None => {
                buf.pop();
                closed |= task::block_on(writeln!(
                    stream.get_mut(),
                    "ERRO comando nao reconhecido '{}'",
                    buf
                ))
                .is_err();
            }
        }
    }
    user.delete_cascade(db);
}

#[async_std::main]
async fn main() {
    let db = Box::leak(Box::new(
        sqlite::Connection::open_thread_safe(":memory:").unwrap(),
    ));
    db.execute(include_str!("./create.sql")).unwrap();
    db.execute(include_str!("./populate.sql")).unwrap();

    let mut rng = rand::thread_rng();
    let rsa_key = Box::leak(Box::new(rsa::RsaPrivateKey::new(&mut rng, 1024).unwrap()));

    let port = std::env::args()
        .nth(1)
        .and_then(|port| port.parse::<u16>().ok())
        .unwrap_or(8888);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr)
        .await
        .unwrap_or_else(|_| panic!("Cannot listen on addr {}", addr));

    while let Some(stream) = listener.incoming().next().await {
        let Ok(stream) = stream else { continue };
        let stream = BufReader::new(stream);
        let db = &*db;
        let rsa_key = &*rsa_key;
        task::spawn(handle_client(db, stream, rsa_key));
    }
}
