use ckb_std::error::SysError;

/// Error
#[repr(i8)]
pub enum Error {
    IndexOutOfBound = 1,
    ItemMissing = 2,
    LengthNotEnough = 3,
    Encoding = 4,
    // Add customized errors here...
    InvalidTypeId = 5,
    InvalidRoomInfo = 6,
    InvalidSignature = 7,
    InvalidCount = 8,
    InvalidTimelock = 9,

    // For rsa
    SyscallError,
    InvalidArgs0,
    InvalidArgs1,
    ValidateSignatureError,
    ArgsMismatched,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

