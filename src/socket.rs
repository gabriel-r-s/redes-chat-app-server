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

impl Stream {
    pub fn new(stream: TcpStream) -> Self {
        let stream = BufReader::new(stream);
        Self {
            stream,
            cipher: symm::Cipher::aes_128_cbc(),
            aes_key: None,
        }
    }

    pub fn set_aes_key(&mut self, aes_key: &str) -> Result<(), IoError> {
        let Ok(aes_key) = base64::decode_block(aes_key) else {
            return Err(IoError::BadCrypto);
        };
        let Ok(aes_key) = TryInto::<AesKey>::try_into(aes_key.as_slice()) else {
            return Err(IoError::BadCrypto);
        };
        self.aes_key = Some(aes_key);
        Ok(())
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
            Ok(_) => return Ok(()),
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
        eprintln!("enc {buf:?}");
        let Ok(dec) = base64::decode_block(buf.trim()) else {
            return Err(IoError::BadCrypto);
        };
        // eprintln!("b64 {dec:?}");
        let Ok(dec) = symm::decrypt(self.cipher, &self.aes_key.unwrap(), None, &dec) else {
            return Err(IoError::BadCrypto);
        };
        // eprintln!("aes {dec:?}");
        let Ok(dec) = std::str::from_utf8(&dec) else {
            return Err(IoError::BadCrypto);
        };
        eprintln!("dec {dec:?}");
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
