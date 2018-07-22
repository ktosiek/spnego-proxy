use gssapi_sys;
use std::error;
use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::slice;
use std::str;

const GSS_C_NO_CONTEXT: gssapi_sys::gss_ctx_id_t = ptr::null_mut();
const GSS_C_NO_CREDENTIAL: gssapi_sys::gss_cred_id_t = ptr::null_mut();
const GSS_C_NO_CHANNEL_BINDINGS: gssapi_sys::gss_channel_bindings_t = ptr::null_mut();
const GSS_C_NO_OID: gssapi_sys::gss_OID = ptr::null_mut();
// gss_display_status types {
const GSS_C_GSS_CODE: ::std::os::raw::c_int = 1;
const GSS_C_MECH_CODE: ::std::os::raw::c_int = 2;
// }

pub struct GSSContext {
    gss_ctx_id: gssapi_sys::gss_ctx_id_t,
}

impl GSSContext {
    pub fn new() -> GSSContext {
        GSSContext {
            gss_ctx_id: GSS_C_NO_CONTEXT,
        }
    }
}

impl Drop for GSSContext {
    fn drop(&mut self) {
        if self.gss_ctx_id != GSS_C_NO_CONTEXT {
            let mut minor: u32 = 0;
            let major = unsafe {
                gssapi_sys::gss_delete_sec_context(
                    &mut minor,
                    &mut self.gss_ctx_id,
                    ptr::null_mut(),
                )
            };
            if major != gssapi_sys::GSS_S_COMPLETE {
                panic!(
                    "Error while dropping GSSContext: {:}",
                    GSSError::new(major, minor, GSS_C_NO_OID)
                )
            }
            self.gss_ctx_id = GSS_C_NO_CONTEXT;
        }
    }
}

// Application-allocated GSS buffer.
// They only point to borrowed data.
pub struct AppBuffer<'a> {
    raw: gssapi_sys::gss_buffer_desc_struct,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> AppBuffer<'a> {
    fn as_gss_buffer(&self) -> *const gssapi_sys::gss_buffer_desc_struct {
        &self.raw
    }
}

impl<'a> From<&'a [u8]> for AppBuffer<'a> {
    fn from(value: &'a [u8]) -> AppBuffer<'a> {
        AppBuffer {
            raw: gssapi_sys::gss_buffer_desc_struct {
                length: value.len(),
                value: value.as_ptr() as *mut ::std::os::raw::c_void,
            },
            phantom: PhantomData,
        }
    }
}

impl<'a> From<&'a Vec<u8>> for AppBuffer<'a> {
    fn from(value: &'a Vec<u8>) -> AppBuffer<'a> {
        AppBuffer {
            raw: gssapi_sys::gss_buffer_desc_struct {
                length: value.len(),
                value: value.as_ptr() as *mut ::std::os::raw::c_void,
            },
            phantom: PhantomData,
        }
    }
}

pub struct GSSBuffer {
    desc: gssapi_sys::gss_buffer_desc_struct,
}

impl GSSBuffer {
    fn new() -> GSSBuffer {
        GSSBuffer {
            desc: gssapi_sys::gss_buffer_desc_struct {
                length: 0,
                value: ptr::null_mut(),
            },
        }
    }

    fn as_gss_buffer_mut(&mut self) -> gssapi_sys::gss_buffer_t {
        &mut self.desc
    }

    pub fn is_empty(&self) -> bool {
        self.desc.length == 0
    }

    pub fn as_bytes(&self) -> &[u8] {
        if self.is_empty() {
            assert!(self.desc.value.is_null());
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.desc.value as *const u8, self.desc.length) }
        }
    }
}

impl Drop for GSSBuffer {
    fn drop(&mut self) {
        if !self.desc.value.is_null() {
            let mut minor: u32 = 0;
            let major = unsafe { gssapi_sys::gss_release_buffer(&mut minor, &mut self.desc) };
            if major != gssapi_sys::GSS_S_COMPLETE {
                panic!(
                    "Error while dropping GSSBuffer: {}",
                    GSSError::new(major, minor, GSS_C_NO_OID)
                )
            }
        }
    }
}

pub struct GSSName {
    name: *mut gssapi_sys::gss_name_struct,
}

impl GSSName {
    fn from_raw(name: *mut gssapi_sys::gss_name_struct) -> GSSName {
        GSSName { name }
    }

    pub fn display_name(&self) -> Option<GSSBuffer> {
        let mut buf = GSSBuffer::new();
        let mut minor: u32 = 0;
        let major = unsafe {
            gssapi_sys::gss_display_name(
                &mut minor,
                self.name,
                buf.as_gss_buffer_mut(),
                &mut GSS_C_NO_OID,
            )
        };
        if major == gssapi_sys::GSS_S_COMPLETE {
            Some(buf)
        } else {
            None
        }
    }
}

impl Drop for GSSName {
    fn drop(&mut self) {
        let mut minor: u32 = 0;
        let major = unsafe { gssapi_sys::gss_release_name(&mut minor, &mut self.name) };
        if major != 0 {
            panic!(
                "Error in gss_release_name: {:}",
                GSSError::new(major, minor, GSS_C_NO_OID)
            )
        }
    }
}

#[derive(Debug)]
pub struct GSSError {
    major: u32,
    minor: u32,
    errors: Vec<String>,
}

impl GSSError {
    fn new(major: u32, minor: u32, mech_type: gssapi_sys::gss_OID) -> GSSError {
        let mut errors = display_major_status(major).unwrap();
        errors.append(&mut display_minor_status(minor, mech_type).unwrap());
        GSSError {
            major,
            minor,
            errors,
        }
    }
}

impl fmt::Display for GSSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.errors.iter().map(|e| f.write_str(e)).collect()
    }
}

impl error::Error for GSSError {
    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub enum AcceptResult {
    ContinueNeeded(GSSBuffer),
    Complete(GSSBuffer, GSSName),
}

pub fn accept_sec_context(
    ctx: &mut GSSContext,
    received_token: &AppBuffer,
) -> Result<AcceptResult, GSSError> {
    let mut minor: u32 = 0;
    let mut output_token = GSSBuffer::new();
    let mut client_name: *mut gssapi_sys::gss_name_struct = ptr::null_mut();
    let mut mech_type: gssapi_sys::gss_OID = ptr::null_mut();
    let major = unsafe {
        gssapi_sys::gss_accept_sec_context(
            &mut minor,
            &mut ctx.gss_ctx_id,
            GSS_C_NO_CREDENTIAL,
            received_token.as_gss_buffer() as *mut gssapi_sys::gss_buffer_desc_struct,
            GSS_C_NO_CHANNEL_BINDINGS,
            &mut client_name,
            &mut mech_type,
            output_token.as_gss_buffer_mut(),
            ptr::null_mut(), // ret_flags
            ptr::null_mut(), // time_rec
            ptr::null_mut(), // delegated_cred_handle
        )
    };
    match major {
        gssapi_sys::GSS_S_CONTINUE_NEEDED => Ok(AcceptResult::ContinueNeeded(output_token)),
        gssapi_sys::GSS_S_COMPLETE => Ok(AcceptResult::Complete(
            output_token,
            GSSName::from_raw(client_name),
        )),
        _ => Err(GSSError::new(major, minor, mech_type)),
    }
}

fn display_major_status(status_code: u32) -> Result<Vec<String>, GSSError> {
    gss_display_status(status_code, GSS_C_GSS_CODE, GSS_C_NO_OID)
}

fn display_minor_status(
    status_code: u32,
    mech_type: gssapi_sys::gss_OID,
) -> Result<Vec<String>, GSSError> {
    gss_display_status(status_code, GSS_C_MECH_CODE, mech_type)
}

fn gss_display_status(
    status_code: u32,
    status_type: ::std::os::raw::c_int,
    mach_type: gssapi_sys::gss_OID,
) -> Result<Vec<String>, GSSError> {
    let mut message_context: u32 = 0;
    let mut result = vec![];
    loop {
        let mut buf = GSSBuffer::new();
        let mut minor: u32 = 0;
        let major = unsafe {
            gssapi_sys::gss_display_status(
                &mut minor,
                status_code,
                status_type,
                mach_type,
                &mut message_context,
                buf.as_gss_buffer_mut(),
            )
        };
        if major != gssapi_sys::GSS_S_COMPLETE {
            return Err(GSSError::new(major, minor, GSS_C_NO_OID));
        }
        result.push(String::from(str::from_utf8(buf.as_bytes()).unwrap()));
        if message_context == 0 {
            break;
        }
    }

    Ok(result)
}
