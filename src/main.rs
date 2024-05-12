use async_std::net::{SocketAddr, TcpListener};
use async_std::prelude::*;
use async_std::task;
use rsa::RsaPrivateKey;
use sqlite::ConnectionThreadSafe as Db;
use std::fmt::Write as _;

mod parse;
use parse::Command;
mod db;
mod socket;
use socket::Stream;

enum IoError {
    Failed,
    Closed,
}

async fn admin(db: &Db) {
    let mut line = String::new();
    loop {
        line.clear();
        let _ = async_std::io::stdin().read_line(&mut line).await;
        let query = db.iterate(&line, |pairs| {
            for &(name, value) in pairs.iter() {
                print!("{}={} | ", name, value.unwrap());
            }
            println!();
            true
        });
        if query.is_err() {
            println!("SQL err");
            continue;
        }
    }
}

async fn auth_client(
    db: &Db,
    stream: &mut Stream,
    rsa_key: &RsaPrivateKey,
    buf: &mut String,
    msg: &mut String,
) -> Result<db::User, IoError> {
    /*
     * REGISTRO usuario             .. REGISTRO_OK
     * AUTENTICACAO usuario         .. CHAVE_PUBLICA rsa_key
     * CHAVE_SIMETRICA RSA(aes_key) ..
     * AES(comandos ...)            .. AES(respostas ...)
     */

    // registro
    buf.clear();
    stream.block_read_plain_line(buf).await?;
    println!("1");
    let name = parse::command_register(&buf)
        .ok_or(IoError::Failed)?
        .to_string();

    if db::User::get_id(db, &name).is_some() {
        stream.write_plain_msg("ERRO usuário já existe\n").await?;
        return Err(IoError::Failed);
    }
    println!("2");
    stream.write_plain_msg("REGISTRO_OK\n").await?;

    // autenticação RSA
    buf.clear();
    stream.block_read_plain_line(buf).await?;
    if parse::command_auth(&buf) != Some(name.as_str()) {
        stream
            .write_plain_msg("ERRO nome de usuário difere")
            .await?;
        return Err(IoError::Failed);
    }
    println!("3");
    let rsa_pub = rsa::RsaPublicKey::from(rsa_key);
    msg.clear();
    writeln!(msg, "CHAVE_PUBLICA {:?}", rsa_pub).map_err(|_| IoError::Closed)?;
    stream.write_plain_msg(&msg).await?;
    println!("4");

    // transmissão chave simétrica
    buf.clear();
    stream.block_read_plain_line(buf).await?;
    let aes_key = if let Some(_aes_key) = parse::command_aes_key(&buf) {
        // rsa_decode(rsa_pri, base64_decode(aes_key))
        "aes_key_goes_here".to_string()
    } else {
        stream
            .write_plain_msg("ERRO transmissao de chave simetrica")
            .await?;
        return Err(IoError::Failed);
    };
    println!("5");

    let Some(id) = db::User::create(db, &name, &aes_key) else {
        stream
            .write_plain_msg("ERRO não foi possível criar usuário")
            .await?;
        return Err(IoError::Failed);
    };
    Ok(db::User { id, name, aes_key })
}

async fn handle_client(db: &'static Db, mut stream: socket::Stream, rsa_key: &RsaPrivateKey) {
    let mut buf = String::new();
    let mut msg = String::new();

    //  dev only!!!!
    // let user = db::User {
    //     id: 1,
    //     name: "admin12_user123".to_string(),
    //     aes_key: "123".to_string(),
    // };
    let mut closed = false;
    let current_user = loop {
        match auth_client(&db, &mut stream, rsa_key, &mut buf, &mut msg).await {
            Ok(user) => {
                break user;
            }
            Err(IoError::Failed) => {
                closed |= stream
                    .write_plain_msg("ERRO tente novamente\n")
                    .await
                    .is_err();
            }
            Err(IoError::Closed) => {
                closed = true;
            }
        }
        if closed {
            return;
        }
    };
    buf.clear();
    'run: while !closed {
        // for new_msg in db::User::drain_msgs(db, current_user.id) {
        //     closed |= stream
        //         .get_mut()
        //         .write_all(new_msg.as_bytes())
        //         .await
        //         .is_err();
        //     if closed {
        //         break 'run;
        //     }
        // }
        match stream.read_line(&mut buf, &current_user.aes_key).await {
            Ok(0) => continue,
            Ok(1..) => { /* ok */ }
            Err(_) => break 'run,
        }

        // TODO AES encrypt/decrypt

        match parse::command(&buf) {
            Some(Command::ListRooms) => {
                msg.clear();
                let _ = write!(&mut msg, "SALAS");
                for room_name in db::Room::get_all(db) {
                    let _ = write!(&mut msg, " {}", room_name);
                }
                let _ = writeln!(&mut msg);
                closed |= stream.write_msg(&msg, &current_user.aes_key).await.is_err();
            }
            Some(Command::LeaveRoom { room_name }) => {
                let Some(room) = db::Room::get(db, room_name) else {
                    closed |= stream
                        .write_msg("ERRO sala não encontrada\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                };
                if !room.is_member(db, current_user.id) {
                    closed |= stream
                        .write_msg("ERRO não é membro da sala\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                if room.is_admin(current_user.id) {
                    closed |= stream
                        .write_msg("ERRO admin deve fechar a sala\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                room.kick(db, current_user.id);
                msg.clear();
                let _ = write!(&mut msg, "SAIU {}", current_user.name);
                room.broadcast(db, &msg, current_user.id, 0);
                closed |= stream
                    .write_msg("SAIR_SALA_OK\n", &current_user.aes_key)
                    .await
                    .is_err();
            }
            Some(Command::CloseRoom { room_name }) => {
                let Some(room) = db::Room::get(db, room_name) else {
                    closed |= stream
                        .write_msg("ERRO sala não encontrada\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                };
                if !room.is_admin(current_user.id) {
                    closed |= stream
                        .write_msg("ERRO não é admin\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                msg.clear();
                let _ = write!(&mut msg, "SALA_FECHADA {}", room_name);
                room.broadcast(db, &msg, current_user.id, 0);
                room.delete_cascade(db);
                closed |= stream
                    .write_msg("FECHAR_SALA_OK\n", &current_user.aes_key)
                    .await
                    .is_err();
            }
            Some(Command::CreateRoom {
                room_name,
                private,
                pass,
            }) => {
                if db::Room::get(db, room_name).is_some() {
                    closed |= stream
                        .write_msg("ERRO sala já existe\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                // TODO decode base64
                // NOTE maybe check length of pass hash SHA-256 = 32B
                if private && pass.is_empty() {
                    closed |= stream
                        .write_msg(
                            "ERRO sala privada deve ter uma senha\n",
                            &current_user.aes_key,
                        )
                        .await
                        .is_err();
                    continue;
                }
                if !db::Room::create(db, room_name, private, pass, current_user.id) {
                    closed |= stream
                        .write_msg("ERRO sala ja existe\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                closed |= stream
                    .write_msg("CRIAR_SALA_OK", &current_user.aes_key)
                    .await
                    .is_err();
            }
            Some(Command::JoinRoom { room_name, pass }) => {
                let Some(room) = db::Room::get(db, room_name) else {
                    closed |= stream
                        .write_msg("ERRO sala não encontrada\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                };
                if room.is_banned(db, current_user.id) {
                    closed |= stream
                        .write_msg("ERRO banido da sala\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                if room.is_member(db, current_user.id) {
                    closed |= stream
                        .write_msg("ERRO já está na sala\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                // TODO decode base64
                if !room.check_pass(db, pass) {
                    closed |= stream
                        .write_msg("ERRO senha incorreta\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                room.add_user(db, current_user.id);

                msg.clear();
                let _ = writeln!(&mut msg, "ENTROU {} {}", room_name, current_user.name);
                room.broadcast(db, &msg, current_user.id, 0);

                msg.clear();
                let _ = write!(&mut msg, "ENTRAR_SALA_OK");
                for user_name in room.get_users(db) {
                    let _ = write!(&mut msg, " {}", user_name);
                }
                let _ = writeln!(&mut msg);
                closed |= stream.write_msg(&msg, &current_user.aes_key).await.is_err();
            }
            Some(Command::SendMsg {
                room_name,
                sent_msg,
            }) => {
                let Some(room) = db::Room::get(db, room_name) else {
                    closed |= stream
                        .write_msg("ERRO sala não encontrada\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                };
                if !room.is_member(db, current_user.id) {
                    closed |= stream
                        .write_msg("ERRO sala não encontrada\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                msg.clear();
                let _ = writeln!(
                    &mut msg,
                    "MENSAGEM {} {} {}",
                    room_name, current_user.name, sent_msg
                );
                room.broadcast(db, &msg, current_user.id, 0);
            }
            Some(Command::BanUser {
                room_name,
                banned_name,
            }) => {
                let Some(room) = db::Room::get(db, room_name) else {
                    closed |= stream
                        .write_msg("ERRO sala não encontrada\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                };
                if !room.is_admin(current_user.id) {
                    closed |= stream
                        .write_msg("ERRO não é admin\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                let Some(banned_id) = db::User::get_id(db, banned_name) else {
                    closed |= stream
                        .write_msg("ERRO usuário não encontrado\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                };
                if banned_id == current_user.id {
                    closed |= stream
                        .write_msg("ERRO não pode banir a si mesmo\n", &current_user.aes_key)
                        .await
                        .is_err();
                    continue;
                }
                if room.kick(db, banned_id) {
                    msg.clear();
                    let _ = writeln!(&mut msg, "SAIU {} {}", room_name, banned_name);
                    room.broadcast(db, &msg, current_user.id, banned_id);
                }
                if room.ban(db, banned_id) {
                    msg.clear();
                    let _ = writeln!(&mut msg, "BANIDO_DA_SALA {}", room_name);
                    db::User::send_to(db, banned_id, &msg);
                }
                closed |= stream
                    .write_msg("BANIMENTO_OK", &current_user.aes_key)
                    .await
                    .is_err();
            }
            None => {
                closed |= stream
                    .write_msg("ERRO comando nao reconhecido\n", &current_user.aes_key)
                    .await
                    .is_err();
            }
        }
    }
    current_user.delete_cascade(db);
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

    task::spawn(admin(db));

    while let Some(stream) = listener.incoming().next().await {
        let Ok(stream) = stream else { continue };
        let stream = Stream::new(stream);
        let db = &*db;
        let rsa_key = &*rsa_key;
        task::spawn(handle_client(db, stream, rsa_key));
    }
}
