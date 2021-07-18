use std::ffi::CString;
use std::ops::BitOr;

use nix::unistd::Uid;

use crate::ffi;
use crate::Error;

/// Login flag constants that can be bitwise OR-ed together
#[derive(Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum LoginFlags {
    /// Sets environment variables set by the setenv keyword
    SetEnv = ffi::LOGIN_SETENV,
    /// Set the group ID and call `initgroups(3)`
    /// Requires the `pwd` field in `setusercontext` to be set
    SetGroup = ffi::LOGIN_SETGROUP,
    /// Sets the login name by setlogin(2)
    /// Requires the `pwd` field in `setusercontext` to be set
    SetLogin = ffi::LOGIN_SETLOGIN,
    /// Sets the `PATH` environment variable
    SetPath = ffi::LOGIN_SETPATH,
    /// Sets the priority by `setpriority(2)`
    SetPriority = ffi::LOGIN_SETPRIORITY,
    /// Sets the various system resources by `setrlimit(2)`
    SetResources = ffi::LOGIN_SETRESOURCES,
    /// Sets the umask by `umask(2)`
    SetUmask = ffi::LOGIN_SETUMASK,
    /// Sets the user ID to `uid` by `setuid(2)`
    SetUser = ffi::LOGIN_SETUSER,
    /// Sets all of the above
    SetAll = ffi::LOGIN_SETALL,
}

/// Bitwise-OR of two or more Login flags
#[derive(Debug, PartialEq)]
pub struct LoginFlagsOr(u32);

impl BitOr for LoginFlags {
    type Output = LoginFlagsOr;

    fn bitor(self, rhs: Self) -> Self::Output {
        LoginFlagsOr((self as u32) | (rhs as u32))
    }
}

impl BitOr for LoginFlagsOr {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOr<LoginFlags> for LoginFlagsOr {
    type Output = Self;

    fn bitor(self, rhs: LoginFlags) -> Self::Output {
        Self(self.0 | (rhs as u32))
    }
}

impl From<LoginFlags> for LoginFlagsOr {
    fn from(f: LoginFlags) -> Self {
        Self(f as u32)
    }
}

impl From<LoginFlagsOr> for u32 {
    fn from(f: LoginFlagsOr) -> Self {
        f.0
    }
}

/// High-level type for `login_cap_t`
pub struct LoginCap {
    ptr: *mut ffi::login_cap_t,
}

impl LoginCap {
    /// Get the login class for the provided user name
    ///
    /// Supplying an empty user name will look up the default user 
    ///
    /// Fails if the username is not a valid UTF8 string,
    /// or if no class can be found for the user
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// assert!(LoginCap::new("default").is_ok());
    /// assert!(LoginCap::new("not-a-class").is_err());
    /// ```
    pub fn new(class: &str) -> Result<Self, Error> {
        let class_ptr = CString::new(class)?.into_raw();
        // safety: class pointer is non-null and points to valid memory
        // On failure, login_getclass returns a null pointer
        let ptr = unsafe { ffi::login_getclass(class_ptr) };

        // safety: pointer should still be non-null, pointing to valid memory
        // Recreate a CString to free the allocated memory
        unsafe { CString::from_raw(class_ptr) };

        if ptr == std::ptr::null_mut() {
            Err(Error::LoginGetClass)
        } else {
            Ok(Self{ ptr })
        }
    }

    /// Get the style of authentication for this user class
    ///
    /// If `style` or `type` are empty, a NULL pointer will be supplied to the FFI call to `login_getstyle`
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// let cap = LoginCap::new("default").unwrap();
    ///
    /// let cap_style = cap.getstyle("passwd", "").unwrap();
    /// assert_eq!(cap_style.as_str(), "passwd");
    ///
    /// let cap_style = cap.getstyle("", "auth-doas").unwrap();
    /// assert_eq!(cap_style.as_str(), "passwd");
    ///
    /// assert!(cap.getstyle("not-a-style", "").is_err());
    /// ```
    ///
    /// From login_getclass(3):
    ///
	/// ```no_build
    /// The login_getstyle() function is used to obtain the style of authentication that should be used for this user class.
    ///
    /// The style argument may either be NULL or the desired style of authentication.
    /// If NULL, the first available authentication style will be used.
    ///
    /// The type argument refers to the type of authentication being performed. 
    /// This is used to override the standard auth entry in the database.
    /// By convention this should be of the form "auth-type".
    ///
    /// Future releases may remove the requirement for the "auth-" prefix and add it if it is missing.
    ///
    /// If type is NULL then only "auth" will be looked at (see login.conf(5)).  The
    ///
    /// login_getstyle() function will return NULL if the desired style of
    /// authentication is not available, or if no style is available.
	/// ```
    pub fn getstyle(&self, style: &str, login_type: &str) -> Result<String, Error> {
        self.check_ptr()?;
        let style_cptr = if style.len() == 0 {
            std::ptr::null_mut()
        } else {
            CString::new(style)?.into_raw()
        };
        let type_cptr = if login_type.len() == 0 {
            std::ptr::null_mut()
        } else {
            CString::new(login_type)?.into_raw()
        };
        // safety: login_cap_t pointer is guaranteed non-null, and should point to valid memory
        // Both style and type pointers are either null, or non-null pointing to valid C strings
        // Null style and type pointers are valid arguments, indicating default values
        // login_getstyle returns null on failure
        let ret_ptr = unsafe { ffi::login_getstyle(self.ptr, style_cptr, type_cptr) };
        if ret_ptr == std::ptr::null_mut() {
            Err(Error::LoginGetStyle)
        } else {
            // safety: pointer is non-null and should point to a valid C string
            let ret_c = unsafe { CString::from_raw(ret_ptr) };
            let ret = Ok(ret_c.to_str()?.to_string());
            // release the pointer so it's not double-freed
            // login_getstyle handles the memory management,
            // since the return pointer in internally allocated
            let _ = ret_c.into_raw();
            ret
        }
    }

    /// Get whether capabilities are found for the login class
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// let cap = LoginCap::new("default").unwrap();
    /// assert!(cap.getcapbool("umask", 022).unwrap());
    /// assert!(cap.getcapbool("not a cap", 0).is_err());
    /// ```
    ///
    /// From `login_getclass(3)`:
    ///
    /// ```no_build
    /// login_getcapbool(3) returns def if no capabilities were found for this class (typically meaning that
    /// the default class was used and the /etc/login.conf file is missing).  It
    /// returns a non-zero value if cap, with no value, was found, zero
    /// otherwise.
    /// ```
    ///
    /// Returns error if default class was used, and `/etc/login.conf` file
    /// is missing
    ///
    /// Returns `Ok(false)` if non-zero value returned
    ///
    /// Returns `Ok(true)` otherwise
    pub fn getcapbool(&self, cap: &str, def: u32) -> Result<bool, Error> {
        self.check_ptr()?;
        let cap_ptr = CString::new(cap)?.into_raw();

        // safety: login_cap_t and cap pointer guaranteed to be non-null,
        // and should point to valid memory
        let ret = unsafe { ffi::login_getcapbool(self.ptr, cap_ptr, def) };

        // safety: pointer should still be non-null, pointing to valid memory
        // Recreate a CString to free the allocated memory
        unsafe { CString::from_raw(cap_ptr) };

        if ret as u32 == def {
            Err(Error::LoginGetCapBool)
        } else if ret != 0 {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    /// Get the capability value for the login class
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// let cap = LoginCap::new("default").unwrap();
    /// let cap_num = cap.getcapnum("umask", 0, -1).unwrap();
    ///
    /// assert_eq!(cap_num, 18);
    /// ```
    ///
    /// From `login_getclass(3)`:
    ///
	/// ```no_build
    /// The login_getcapnum() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.
    ///
    /// See login.conf(5) for a discussion of the various textual forms the value may take.
    /// ```
    pub fn getcapnum(&self, cap: &str, def: i64, err: i64) -> Result<i64, Error> {
        self.check_ptr()?;
        let cap_ptr = CString::new(cap)?.into_raw();

        // safety: login_cap_t and cap pointer guaranteed to be non-null,
        // and should point to valid memory
        let ret = unsafe { ffi::login_getcapnum(self.ptr, cap_ptr, def, err) };

        // safety: pointer should still be non-null, pointing to valid memory
        // Recreate a CString to free the allocated memory
        unsafe { CString::from_raw(cap_ptr) };

        if ret == err {
            Err(Error::LoginGetCapErr(err))
        } else {
            Ok(ret)
        }
    }

    /// Get the capability value for the login class
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// let cap = LoginCap::new("default").unwrap();
    /// let cap_size = cap.getcapsize("umask", 0, -1).unwrap();
    ///
    /// assert_eq!(cap_size, 18);
    /// ```
    ///
    /// From `login_getclass(3)`:
    ///
	/// ```no_build
    /// The login_getcapsize() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.
    ///
    /// See login.conf(5) for a discussion of the various textual forms the value may take.
    /// ```
    pub fn getcapsize(&self, cap: &str, def: i64, err: i64) -> Result<i64, Error> {
        self.check_ptr()?;
        let cap_ptr = CString::new(cap)?.into_raw();

        // safety: login_cap_t and cap pointer guaranteed to be non-null,
        // and should point to valid memory
        let ret = unsafe { ffi::login_getcapsize(self.ptr, cap_ptr, def, err) };

        // safety: pointer should still be non-null, pointing to valid memory
        // Recreate a CString to free the allocated memory
        unsafe { CString::from_raw(cap_ptr) };

        if ret == err {
            Err(Error::LoginGetCapErr(err))
        } else {
            Ok(ret)
        }
    }

    /// Get the capability value for the login class
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// let cap = LoginCap::new("default").unwrap();
    /// let cap_str = cap.getcapstr("localcipher", "default", "no cipher").unwrap();
    /// assert_eq!(cap_str.as_str(), "blowfish,a");
    /// ```
    ///
    /// From `login_getclass(3)`:
    ///
	/// ```no_build
    /// The login_getcapstr() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.
    ///
    /// See login.conf(5) for a discussion of the various textual forms the value may take.
    /// ```
    pub fn getcapstr(&self, cap: &str, def: &str, err: &str) -> Result<String, Error> {
        self.check_ptr()?;
        let cap_ptr = CString::new(cap)?.into_raw();
        let def_ptr = CString::new(def)?.into_raw();
        let err_ptr = CString::new(err)?.into_raw();

        // safety: login_cap_t and cap pointer guaranteed to be non-null,
        // and should point to valid memory
        let ret_ptr = unsafe { ffi::login_getcapstr(self.ptr, cap_ptr, def_ptr, err_ptr) };
        let ret = if ret_ptr == std::ptr::null_mut() || ret_ptr == err_ptr {
            Err(Error::LoginGetCapErrStr(err.into()))
        } else if ret_ptr == def_ptr {
            Ok(def.into())
        } else {
            // safety: the returned pointer should either be `def`, or the
            // value of the capability
            //
            // Either way, the value is guaranteed non-null, and should point
            // to valid memory
            let ret_cstr = unsafe { CString::from_raw(ret_ptr) };
            Ok(ret_cstr.to_str()?.into())
        };

        // safety: pointers should still be non-null, pointing to valid memory
        // Recreate a CString to free the allocated memory
        unsafe {
            CString::from_raw(cap_ptr);
            CString::from_raw(def_ptr);
            CString::from_raw(err_ptr);
        }

        ret
    }

    /// Get the capability value for the login class
    ///
    /// Example:
    ///
    /// ```rust
    /// # use login_cap::LoginCap;
    /// let cap = LoginCap::new("default").unwrap();
    /// let cap_time = cap.getcaptime("umask", 0, -1).unwrap();
    ///
    /// assert_eq!(cap_time, 18);
    /// ```
    ///
    /// From `login_getclass(3)`:
    ///
	/// ```no_build
    /// The login_getcaptime() function queries the database entry for a field
    /// named cap.  If the field is found, its value is returned.  If the field
    /// is not found, the value specified by def is returned.  If an error is
    /// encountered while trying to find the field, err is returned.
    ///
    /// See login.conf(5) for a discussion of the various textual forms the value may take.
    /// ```
    pub fn getcaptime(&self, cap: &str, def: i64, err: i64) -> Result<i64, Error> {
        self.check_ptr()?;
        let cap_ptr = CString::new(cap)?.into_raw();

        // safety: login_cap_t and cap pointer guaranteed to be non-null,
        // and should point to valid memory
        let ret = unsafe { ffi::login_getcaptime(self.ptr, cap_ptr, def, err) };

        // safety: pointer should still be non-null, pointing to valid memory
        // Recreate a CString to free the allocated memory
        unsafe { CString::from_raw(cap_ptr) };

        if ret == err {
            Err(Error::LoginGetCapErr(err))
        } else {
            Ok(ret)
        }
    }

    /// Set user resources according to `flags`
    ///
    /// The `flags` argument can be produced by ORing together two or more
    /// `LoginFlags` variants, or converting a single `LoginFlags` variant.
    ///
    /// Example: 
    ///
    /// ```rust
    /// # use nix::unistd::Uid;
    /// # use login_cap::{LoginCap, LoginFlags};
    /// if let Ok(cap) = LoginCap::new("default") {
    ///     let nobody_uid = Uid::from_raw(32767);
    ///     cap.setusercontext(
    ///         None,
    ///         nobody_uid,
    ///         LoginFlags::SetEnv | LoginFlags::SetUmask,
    ///     ).unwrap();
    ///     /* or */
    ///     cap.setusercontext(
    ///         None,
    ///         nobody_uid,
    ///         LoginFlags::SetEnv.into(),
    ///     ).unwrap();
    /// }
    /// ```
    ///
    /// From `login_getclass(3)`:
    ///
	/// ```no_build
    /// The setusercontext() function sets the resources according to flags.  The
    /// lc argument, if not NULL, contains the class information that should be
    /// used.  The pwd argument, if not NULL, provides information about the
    /// user.  Both lc and pwd cannot be NULL.  The uid argument is used in place
    /// of the user ID contained in the pwd structure when calling setuid(2).
    /// The setusercontext() function returns 0 on success and -1 on failure.
	/// ```
    // FIXME: change to using a nix::unistd::User for pwd if conversion from
    // nix::unistd::User to libc::passwd is merged upstream
    pub fn setusercontext(
        &self,
        pwd: Option<&mut libc::passwd>,
        uid: Uid,
        flags: LoginFlagsOr
    ) -> Result<(), Error> {
        self.check_ptr()?;
        let pwd_ptr = match pwd {
            Some(p) => p as *mut libc::passwd,
            None => std::ptr::null_mut(),
        };
        // safety: login_cap_t pointer guaranteed non-null, and should point to valid memory
        // passwd ptr is either null (valid), or non-null pointing to valid memory
        let res = unsafe { ffi::setusercontext(self.ptr, pwd_ptr, uid.into(), flags.0) };
        if res != 0 {
            Err(Error::LoginSetUserContext)
        } else {
            Ok(())
        }
    }

    fn check_ptr(&self) -> Result<(), Error> {
        if self.ptr == std::ptr::null_mut() {
            Err(Error::NullPtr)
        } else {
            Ok(())
        }
    }
}

impl Drop for LoginCap {
    fn drop(&mut self) {
        if self.ptr != std::ptr::null_mut() {
            // safety: with the null check above,
            // login_cap_t pointer is guaranteed non-null, and
            // should point to valid memory
            unsafe { ffi::login_close(self.ptr) }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_getclass() {
        assert!(LoginCap::new("default").is_ok());
        assert!(LoginCap::new("not_a_class").is_err());
    }

    #[test]
    fn test_getcapstr() {
        let cap = LoginCap::new("default").unwrap();
        let cap_str = cap.getcapstr("localcipher", "default", "error").unwrap();
        assert_eq!(cap_str.as_str(), "blowfish,a");

        // no capability found
        let cap_err = cap.getcapstr("not a cap", "default", "error").unwrap();
        assert_eq!(cap_err.as_str(), "default");

        // FIXME: add error test after figuring out how to reliably induce an error
    }

    #[test]
    fn test_setusercontext() {
        let cap = LoginCap::new("default").unwrap();
        let nobody_uid = Uid::from_raw(32767);

        assert!(
            cap.setusercontext(
                None,
                nobody_uid,
                LoginFlags::SetEnv | LoginFlags::SetUmask,
            )
            .is_ok()
        );
        assert!(
            cap.setusercontext(
                None,
                nobody_uid,
                LoginFlags::SetEnv.into(),
            )
            .is_ok()
        );
        assert!(
            cap.setusercontext(
                None,
                nobody_uid,
                LoginFlags::SetAll.into()
            )
            .is_err()
        );
    }
}
