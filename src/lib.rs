use std::ffi::CString;

use login_cap_sys as ffi;

mod login;
mod error;

pub use error::Error;
pub use login::*;

/// Bit flags which can be returned by authenticate()/auth_scan()
#[repr(u32)]
pub enum AuthFlags {
    /// User authenticated
    Okay = ffi::AUTH_OKAY,
    /// Authenticated as root
    RootOkay = ffi::AUTH_ROOTOKAY,
    /// Secure login
    Secure = ffi::AUTH_SECURE,
    /// Silent rejection
    Silent = ffi::AUTH_SILENT,
    /// A challenge was given
    Challenge = ffi::AUTH_CHALLENGE,
    /// Account expired
    Expired = ffi::AUTH_EXPIRED,
    /// Password expired
    PwExpired = ffi::AUTH_PWEXPIRED,
    /// (AUTH_OKAY | AUTH_ROOTOKAY | AUTH_SECURE)
    Allow = ffi::AUTH_ALLOW,
}

/// Check whether the path is secure
///
/// Returns Ok(true) if the path is secure, Ok(false) otherwise
///
/// Returns Err if an error occurs
///
/// Example:
///
/// ```rust
/// # use login_cap::secure_path;
/// assert!(secure_path("/etc/passwd").unwrap());
/// assert_eq!(secure_path("/etc/").unwrap(), false);
/// ```
///
/// From `login_getclass(3)`:
///
/// ```no_build
/// The secure_path() function takes a path name and returns 0 if the path
/// name is secure, -1 if not.  To be secure a path must exist, be a regular
/// file (and not a directory), owned by root, and only writable by the owner
/// (root).
/// ```
pub fn secure_path(path: &str) -> Result<bool, Error> {
    let path_ptr = CString::new(path)?.into_raw();
    // safety: pointer is guaranteed non-null, and points to valid memory
    let ret = unsafe { ffi::secure_path(path_ptr) };

    // safety: pointer is guaranteed non-null, and should still point to valid memory
    // Recreate a CString to free allocated memory
    unsafe { CString::from_raw(path_ptr) };

    Ok(ret == 0)
}

/// Set the class context using resources defined by flags
///
/// Example:
///
/// ```rust
/// # use login_cap::{setclasscontext, LoginFlags};
/// assert!(setclasscontext("default", LoginFlags::SetEnv.into()).is_ok());
/// assert!(setclasscontext("default", LoginFlags::SetEnv | LoginFlags::SetUmask).is_ok());
/// // invalid class
/// assert!(setclasscontext("not-a-class", LoginFlags::SetEnv.into()).is_err());
/// ```
///
/// From `login_getclass(3)`:
///
///```no_build
/// The setclasscontext() function takes class, the name of a user class, and
/// sets the resources defined by that class according to flags.  Only the
/// LOGIN_SETPATH, LOGIN_SETPRIORITY, LOGIN_SETRESOURCES, and LOGIN_SETUMASK
/// bits are used (see setusercontext() below).  It returns 0 on success and
/// -1 on failure.
///```
pub fn setclasscontext(class: &str, flags: LoginFlagsOr) -> Result<(), Error> {
    let class_ptr = CString::new(class)?.into_raw();
    // safety: pointer is guaranteed non-null, and points to valid memory
    let ret = unsafe { ffi::setclasscontext(class_ptr, flags.into()) };

    // safety: pointer is guaranteed non-null, and should still point to valid memory
    // Recreate a CString to free allocated memory
    unsafe { CString::from_raw(class_ptr) };

    if ret == -1 {
        Err(Error::SetClassContext)
    } else {
        Ok(())
    }
}
