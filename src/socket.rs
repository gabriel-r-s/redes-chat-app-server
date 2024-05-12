use async_std::io::BufReader;
use async_std::net::TcpStream;
use async_std::prelude::*;
use core::time::Duration;

use crate::IoError;

const READ_TIMEOUT: Duration = Duration::from_millis(500);

pub struct Stream {
    stream: BufReader<TcpStream>,
    #[allow(unused)]
    buf_aes: Vec<u8>,
    #[allow(unused)]
    buf_base64: String,
}

impl Stream {
    pub fn new(stream: TcpStream) -> Self {
        let stream = BufReader::new(stream);
        let buf_aes = Vec::new();
        let buf_base64 = String::new();
        Self {
            stream,
            buf_aes,
            buf_base64,
        }
    }

    pub async fn block_read_plain_line<'a>(
        &mut self,
        buf: &'a mut String,
    ) -> Result<usize, IoError> {
        self.stream
            .read_line(buf)
            .await
            .map_err(|_| IoError::Closed)
    }

    pub async fn read_plain_line<'a>(&mut self, buf: &'a mut String) -> Result<usize, IoError> {
        let read = async_std::future::timeout(READ_TIMEOUT, self.stream.read_line(buf)).await;

        match read {
            Ok(Ok(n @ 1..)) => Ok(n),
            Err(_) => Ok(0),
            Ok(Ok(0) | Err(_)) => Err(IoError::Closed),
        }
    }

    pub async fn read_line<'a>(
        &mut self,
        buf: &'a mut String,
        aes_key: &str,
    ) -> Result<usize, IoError> {
        // TODO self.stream.read_line(&mut self.buf_base64).await.map_err(|_| IoError::Closed)?;
        // TODO decode_base64(&mut self.vec, &self.buf_base64)
        // TODO decode_aes(buf, &self.vec)
        // TODO buf += \n
        // TODO return buf
        let _ = aes_key;
        self.read_plain_line(buf).await
    }

    pub async fn write_plain_msg(&mut self, msg: &str) -> Result<(), IoError> {
        self.stream
            .get_mut()
            .write_all(msg.as_bytes())
            .await
            .map(|_| ())
            .map_err(|_| IoError::Closed)
    }

    pub async fn write_msg(&mut self, msg: &str, aes_key: &str) -> Result<(), IoError> {
        // TODO encode_aes(&self.buf_aes, msg)
        // TODO encode_base64(&mut self.buf_base64, &self.buf_aes)
        // TODO buf_base64 += \n
        // TODO self.stream.get_mut().write_all(self.buf_base64.as_bytes())
        let _ = aes_key;
        self.write_plain_msg(msg).await
    }
}
