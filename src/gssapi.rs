use gssapi_sys;
use std::marker::PhantomData;
use std::ptr;
use std::slice;
use std::str;

const GSS_C_NO_CONTEXT: gssapi_sys::gss_ctx_id_t = ptr::null_mut();
const GSS_C_NO_CREDENTIAL: gssapi_sys::gss_cred_id_t = ptr::null_mut();
const GSS_C_NO_CHANNEL_BINDINGS: gssapi_sys::gss_channel_bindings_t = ptr::null_mut();
const GSS_C_NO_OID: gssapi_sys::gss_OID = ptr::null_mut();

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
        unsafe {
            let mut minor: u32 = 0;
            if self.gss_ctx_id != GSS_C_NO_CONTEXT {
                gssapi_sys::gss_delete_sec_context(
                    &mut minor,
                    &mut self.gss_ctx_id,
                    ptr::null_mut(),
                );
                self.gss_ctx_id = GSS_C_NO_CONTEXT;
            }
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
    fn as_gss_buffer_mut(&mut self) -> gssapi_sys::gss_buffer_t {
        &mut self.raw
    }

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

    pub fn as_bytes(&self) -> &[u8] {
        if self.desc.value.is_null() {
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
            unsafe {
                gssapi_sys::gss_release_buffer(&mut minor, &mut self.desc);
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

    // TODO: gss_release_name

    fn as_gss_name_mut(&mut self) -> *mut gssapi_sys::gss_name_struct {
        self.name
    }

    pub fn display_name(&self) -> Option<GSSBuffer> {
        let mut buf = GSSBuffer::new();
        let mut minor: u32 = 0;
        let mut major = 0;
        unsafe {
            major = gssapi_sys::gss_display_name(
                &mut minor,
                self.name,
                buf.as_gss_buffer_mut(),
                &mut GSS_C_NO_OID,
            );
        }
        if major == gssapi_sys::GSS_S_COMPLETE {
            Some(buf)
        } else {
            None
        }
    }
}

pub struct GSSError {
    major: u32,
    minor: u32,
}

pub enum AcceptResult {
    ContinueNeeded(GSSBuffer),
    Complete(GSSName),
}

pub fn accept_sec_context(
    ctx: &mut GSSContext,
    received_token: &AppBuffer,
) -> Result<AcceptResult, GSSError> {
    let mut major: u32 = 0;
    let mut minor: u32 = 0;
    let mut output_token = GSSBuffer::new();
    let mut client_name: *mut gssapi_sys::gss_name_struct = ptr::null_mut();
    unsafe {
        major = gssapi_sys::gss_accept_sec_context(
            &mut minor,
            &mut ctx.gss_ctx_id,
            GSS_C_NO_CREDENTIAL,
            received_token.as_gss_buffer() as *mut gssapi_sys::gss_buffer_desc_struct,
            GSS_C_NO_CHANNEL_BINDINGS,
            &mut client_name,
            ptr::null_mut(), // mech_type
            output_token.as_gss_buffer_mut(),
            ptr::null_mut(), // ret_flags
            ptr::null_mut(), // time_rec
            ptr::null_mut(), // delegated_cred_handle
        );
    }
    match major {
        gssapi_sys::GSS_S_CONTINUE_NEEDED => Ok(AcceptResult::ContinueNeeded(output_token)),
        gssapi_sys::GSS_S_COMPLETE => Ok(AcceptResult::Complete(GSSName::from_raw(client_name))),
        _ => Err(GSSError { major, minor }),
    }
}
