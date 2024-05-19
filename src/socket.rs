use async_std::io::BufReader;
use async_std::net::TcpStream;
use async_std::prelude::*;
use core::time::Duration;
use openssl::{base64, symm};
use std::fmt::Write as _;

use crate::{AesKey, IoError};

const READ_TIMEOUT: Duration = Duration::from_millis(500);

pub struct Stream {
    stream: BufReader<TcpStream>,
    cipher: symm::Cipher,
    aes_key: Option<AesKey>,
}

impl Drop for Stream {
    fn drop(&mut self) {
        eprintln!(
            "(SERVER)\tClosed connection {:?}",
            self.stream.get_ref().peer_addr().unwrap()
        );
    }
}

impl Stream {
    pub fn new(stream: TcpStream) -> Self {
        eprintln!("(SERVER)\tNew connection {:?}", stream.peer_addr().unwrap());
        let stream = BufReader::new(stream);
        Self {
            stream,
            cipher: symm::Cipher::aes_256_ecb(),
            aes_key: None,
        }
    }

    pub fn set_aes_key(&mut self, aes_key: AesKey) {
        self.aes_key = Some(aes_key);
    }

    pub async fn block_read_plain_line<'a>(
        &mut self,
        buf: &'a mut String,
    ) -> Result<usize, IoError> {
        buf.clear();
        self.stream
            .read_line(buf)
            .await
            .map_err(|_| IoError::Closed)
    }

    pub async fn read_plain_line<'a>(&mut self, buf: &'a mut String) -> Result<(), IoError> {
        buf.clear();
        let read = async_std::io::timeout(READ_TIMEOUT, self.stream.read_line(buf)).await;

        match read {
            Err(err) if err.kind() == async_std::io::ErrorKind::TimedOut => {
                return Err(IoError::Timeout);
            }
            Err(_) => return Err(IoError::Closed),
            Ok(_) => {
                eprintln!("(MSG)\t{buf:?}");
                return Ok(());
            }
        }

        //if let Ok(Err(_)) = read {
        //    return Err(IoError::Closed);
        //}
        //if read.is_err() || buf.is_empty() {
        //    return Err(IoError::Timeout);
        //}
        //return Ok(());
    }

    pub async fn read_line(&mut self, buf: &mut String) -> Result<(), IoError> {
        self.read_plain_line(buf).await?;
        // eprintln!("enc {buf:?}");
        let Ok(dec) = base64::decode_block(buf.trim()) else {
            return Err(IoError::BadCrypto);
        };
        let Ok(dec) = symm::decrypt(self.cipher, &self.aes_key.unwrap(), None, &dec) else {
            return Err(IoError::BadCrypto);
        };
        let Ok(dec) = std::str::from_utf8(&dec) else {
            return Err(IoError::BadCrypto);
        };
        eprintln!("(MSG)\t{dec:?}");
        buf.clear();
        let _ = writeln!(buf, "{}", dec);
        Ok(())
    }

    pub async fn write_plain_msg(&mut self, msg: &str) -> Result<(), IoError> {
        self.stream
            .get_mut()
            .write_all(msg.as_bytes())
            .await
            .unwrap();
        Ok(())
        // .map(|_| ())
        // .map_err(|_| IoError::Closed)
    }

    pub async fn write_msg(&mut self, msg: &str) -> Result<(), IoError> {
        let Ok(enc) = symm::encrypt(
            self.cipher,
            &self.aes_key.unwrap(),
            None,
            msg.trim().as_bytes(),
        ) else {
            return Err(IoError::BadCrypto);
        };
        let mut enc = base64::encode_block(&enc);
        let _ = writeln!(&mut enc);
        // eprintln!("writing {:?}", msg);
        // eprintln!("encoded {:?}", enc);
        self.write_plain_msg(&enc).await
    }
}
