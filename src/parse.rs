pub fn command_register<'a>(line: &'a str) -> Option<&'a str> {
    let mut split = line.split_whitespace();
    match (split.next(), split.next()) {
        (Some("REGISTRO"), Some(username)) => Some(username),
        _ => None,
    }
}

pub fn command_auth<'a>(line: &'a str) -> Option<&'a str> {
    let mut split = line.split_whitespace();
    match (split.next(), split.next()) {
        (Some("AUTENTICACAO"), Some(username)) => Some(username),
        _ => None,
    }
}

pub fn command_aes_key<'a>(line: &'a str) -> Option<&'a str> {
    let mut split = line.split_whitespace();
    match (split.next(), split.next()) {
        (Some("CHAVE_SIMETRICA"), Some(key)) => Some(key),
        _ => None,
    }
}

pub fn command<'a>(line: &'a str) -> Option<Command<'a>> {
    let mut split = line.split_whitespace();
    match split.next() {
        Some("LISTAR_SALAS") => Some(Command::ListRooms),
        Some("SAIR_SALA") => {
            let room_name = split.next()?;
            Some(Command::LeaveRoom { room_name })
        }
        Some("FECHAR_SALA") => {
            let room_name = split.next()?;
            Some(Command::CloseRoom { room_name })
        }
        Some("CRIAR_SALA") => {
            let private = match split.next() {
                Some("PUBLICA") => false,
                Some("PRIVADA") => true,
                _ => return None,
            };
            let room_name = split.next()?;
            let pass = split.next().unwrap_or("");
            Some(Command::CreateRoom {
                room_name,
                private,
                pass,
            })
        }
        Some("ENTRAR_SALA") => {
            let room_name = split.next()?;
            let pass = split.next().unwrap_or("");
            Some(Command::JoinRoom { room_name, pass })
        }
        Some("ENVIAR_MENSAGEM") => {
            let room_name = split.next()?;
            let sent_msg = split.next().unwrap_or("");
            Some(Command::SendMsg {
                room_name,
                sent_msg,
            })
        }
        Some("BANIR_USUARIO") => {
            let room_name = split.next()?;
            let banned_name = split.next()?;
            Some(Command::BanUser {
                room_name,
                banned_name,
            })
        }
        _ => None,
    }
}

#[derive(Debug)]
pub enum Command<'a> {
    ListRooms,
    LeaveRoom {
        room_name: &'a str,
    },
    CloseRoom {
        room_name: &'a str,
    },
    CreateRoom {
        room_name: &'a str,
        private: bool,
        pass: &'a str,
    },
    JoinRoom {
        room_name: &'a str,
        pass: &'a str,
    },
    SendMsg {
        room_name: &'a str,
        sent_msg: &'a str,
    },
    BanUser {
        room_name: &'a str,
        banned_name: &'a str,
    },
}
