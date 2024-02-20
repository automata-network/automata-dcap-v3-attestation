use std::{borrow::Cow, fs, io::ErrorKind};

pub fn read_file_or_hex(path_or_data: &str) -> Result<Vec<u8>, String> {
    let data = match fs::read_to_string(path_or_data) {
        Ok(data) => Cow::Owned(data),
        Err(err) if err.kind() == ErrorKind::NotFound => Cow::Borrowed(path_or_data),
        err => return Err(format!("{:?}", err)),
    };
    let mut data = data.as_ref();
    if data.starts_with("0x") {
        data = &data[2..];
    }
    match hex::decode(data) {
        Ok(data) => Ok(data),
        Err(err) => {
            return Err(format!(
                "file not found: {:?} or hex decode fail: {:?}",
                path_or_data, err
            ));
        }
    }
}

pub fn read_file(path: &str) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|err| format!("read file={:?} fail: {:?}", path, err))
}

pub fn debug<N: std::fmt::Debug>(n: N) -> String {
    format!("{:?}", n)
}
