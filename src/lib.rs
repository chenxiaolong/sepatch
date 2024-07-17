// SPDX-FileCopyrightText: 2014-2024 Andrew Gunnerson
// SPDX-License-Identifier: LGPL-2.1-or-later
// Based on DualBootPatcher and Custota code.

//! This module contains some small wrappers around the libsepol functionality
//! needed to patch binary SELinux policy files. There is a ton of unsafe things
//! due to the nature of how libsepol organizes its data structures.
//!
//! All memory allocation errors, out of bounds errors, and libsepol invariant
//! violations will result in panics. All other errors are returned.

mod bindings;

use core::slice;
use std::{
    ffi::{c_char, c_void, CStr, CString},
    io::{self, Read, Write},
    iter::FlatMap,
    marker::PhantomData,
    mem::{self, MaybeUninit},
    num::{NonZeroU16, NonZeroU32},
    ops::{Deref, DerefMut, RangeInclusive},
    ptr::{self, NonNull},
};

use libc::{free, malloc, reallocarray, strdup};
use num_traits::PrimInt;

use crate::bindings::{
    avtab_datum, avtab_extended_perms, avtab_hash_wrapper, avtab_insert, avtab_insert_nonunique,
    avtab_key, avtab_node, avtab_ptr_t, avtab_search_node, avtab_search_node_next, class_datum,
    ebitmap, ebitmap_cpy, ebitmap_destroy, ebitmap_get_bit, ebitmap_init_wrapper,
    ebitmap_next_wrapper, ebitmap_node, ebitmap_node_get_bit_wrapper, ebitmap_set_bit,
    ebitmap_start_wrapper, hashtab_search, msg_non_variadic_callback_data, perm_datum, policydb,
    policydb_destroy, policydb_from_image, policydb_index_classes, policydb_index_decls_wrapper,
    policydb_index_others, policydb_init, policydb_to_image, role_datum, sepol_handle,
    sepol_handle_create, sepol_handle_destroy, sepol_msg_set_non_variadic_callback, symtab_insert,
    type_datum, type_datum_init, AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY,
    AVTAB_TRANSITION, AVTAB_XPERMS, AVTAB_XPERMS_ALLOWED, AVTAB_XPERMS_AUDITALLOW,
    AVTAB_XPERMS_DONTAUDIT, AVTAB_XPERMS_IOCTLDRIVER, AVTAB_XPERMS_IOCTLFUNCTION, CEXPR_NAMES,
    CEXPR_TYPE, SCOPE_DECL, SYM_CLASSES, SYM_ROLES, SYM_TYPES, TYPE_ATTRIB, TYPE_TYPE,
};

/// Container for storing warning and error messages emitted during policy load
/// and save operations.
struct MessageHandle {
    handle: *mut sepol_handle,
    data: msg_non_variadic_callback_data,
    messages: Vec<String>,
}

impl MessageHandle {
    pub fn new() -> Box<Self> {
        let handle = unsafe { sepol_handle_create() };
        if handle.is_null() {
            panic!("Failed to allocate sepol_handle");
        }

        let messages = Vec::new();
        let data = msg_non_variadic_callback_data {
            func: Some(Self::callback),
            data: ptr::null_mut(),
        };

        let mut result = Box::new(Self {
            handle,
            data,
            messages,
        });

        // The pointer is stable because we're always boxed.
        result.data.data = (result.as_mut() as *mut MessageHandle).cast();

        unsafe {
            sepol_msg_set_non_variadic_callback(handle, &mut result.data);
        }

        result
    }

    unsafe extern "C" fn callback(
        varg: *mut c_void,
        _handle: *mut sepol_handle,
        msg: *const c_char,
    ) {
        let mh = varg as *mut Self;
        let msg = CStr::from_ptr(msg);
        (*mh)
            .messages
            .push(msg.to_str().unwrap_or_default().to_owned());
    }

    pub fn into_vec(mut self) -> Vec<String> {
        // Can't move out of the struct because we manually implement Drop.
        let mut ret = Vec::new();
        mem::swap(&mut ret, &mut self.messages);
        ret
    }
}

impl Drop for MessageHandle {
    fn drop(&mut self) {
        unsafe { sepol_handle_destroy(self.handle) }
    }
}

/// A wrapper around an arbitrary C buffer that is automatically freed on drop
/// if it is not null.
struct CBuf {
    data: *mut c_void,
    len: usize,
}

impl CBuf {
    fn new() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

impl Drop for CBuf {
    fn drop(&mut self) {
        unsafe {
            free(self.data);
        }
    }
}

/// An immutable reference to an ebitmap.
struct BitmapRef(PhantomData<()>);

impl BitmapRef {
    #[inline]
    unsafe fn from_ptr<'a>(ptr: *const ebitmap) -> &'a Self {
        &*ptr.cast()
    }

    #[inline]
    unsafe fn from_mut_ptr<'a>(ptr: *mut ebitmap) -> &'a mut Self {
        &mut *ptr.cast()
    }

    #[inline]
    fn as_ptr(&self) -> *const ebitmap {
        self as *const _ as *const _
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut ebitmap {
        self as *mut _ as *mut _
    }

    /// Add a value to the bitmap. This will panic if C memory allocation fails.
    /// This is a no-op if the value already exists in the bitmap.
    pub fn insert(&mut self, value: u32) {
        unsafe {
            if ebitmap_set_bit(self.as_mut_ptr(), value, 1) != 0 {
                panic!("Failed to insert {value}");
            }
        }
    }

    /// Create a iterator that yields all values in the bitmap.
    pub fn iter(&self) -> BitmapIter {
        BitmapIter::new(self)
    }
}

struct Bitmap {
    ebitmap: ebitmap,
}

impl Bitmap {
    /// Create an empty bitmap.
    pub fn new() -> Self {
        unsafe {
            let mut ebitmap = MaybeUninit::<ebitmap>::uninit();
            ebitmap_init_wrapper(ebitmap.as_mut_ptr());

            Self {
                ebitmap: ebitmap.assume_init(),
            }
        }
    }
}

impl Drop for Bitmap {
    fn drop(&mut self) {
        unsafe {
            ebitmap_destroy(&mut self.ebitmap);
        }
    }
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Bitmap {
    /// Clone the bitmap. This will panic if C memory allocation fails.
    fn clone(&self) -> Self {
        unsafe {
            let mut ebitmap = MaybeUninit::<ebitmap>::uninit();
            if ebitmap_cpy(ebitmap.as_mut_ptr(), &self.ebitmap) != 0 {
                panic!("Failed to clone bitmap");
            }

            Self {
                ebitmap: ebitmap.assume_init(),
            }
        }
    }
}

impl Deref for Bitmap {
    type Target = BitmapRef;

    fn deref(&self) -> &Self::Target {
        unsafe { BitmapRef::from_ptr(&self.ebitmap) }
    }
}

impl DerefMut for Bitmap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { BitmapRef::from_mut_ptr(&mut self.ebitmap) }
    }
}

impl IntoIterator for Bitmap {
    type Item = u32;

    type IntoIter = BitmapIntoIter;

    /// Create a consuming iterator that yields all values in the bitmap. The
    /// bitmap cannot be used after calling this. Note that memory for consumed
    /// values isn't released until the iterator is dropped.
    fn into_iter(self) -> Self::IntoIter {
        BitmapIntoIter::new(self)
    }
}

impl<'a> IntoIterator for &'a BitmapRef {
    type Item = u32;

    type IntoIter = BitmapIter<'a>;

    /// Same as [`BitmapRef::iter`].
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

macro_rules! define_bitmap_iter {
    ($name:ident$(<$lt:lifetime>)?, $bitmap:ident) => {
        pub struct $name$(<$lt>)? {
            bitmap: $(& $lt)? $bitmap,
            node: *mut ebitmap_node,
            bit: u32,
        }

        impl$(<$lt>)? $name$(<$lt>)? {
            fn new(bitmap: $(& $lt)? $bitmap) -> Self {
                unsafe {
                    let mut node = ptr::null_mut();
                    let bit = ebitmap_start_wrapper(bitmap.as_ptr(), &mut node);

                    let mut result = Self { bitmap, node, bit };
                    result.move_to_nonzero();
                    result
                }
            }

            fn move_to_nonzero(&mut self) {
                unsafe {
                    while self.bit < (*self.bitmap.as_ptr()).highbit
                        && ebitmap_node_get_bit_wrapper(self.node, self.bit) == 0
                    {
                        self.bit = ebitmap_next_wrapper(&mut self.node, self.bit);
                    }
                }
            }

            fn move_to_next_nonzero(&mut self) {
                unsafe {
                    self.bit = ebitmap_next_wrapper(&mut self.node, self.bit);
                    self.move_to_nonzero();
                }
            }
        }

        impl$(<$lt>)? Iterator for $name$(<$lt>)? {
            type Item = u32;

            fn next(&mut self) -> Option<Self::Item> {
                unsafe {
                    if self.bit >= (*self.bitmap.as_ptr()).highbit {
                        return None;
                    }
                }

                let value = self.bit;

                self.move_to_next_nonzero();

                Some(value)
            }
        }
    };
}

define_bitmap_iter!(BitmapIter<'a>, BitmapRef);
define_bitmap_iter!(BitmapIntoIter, Bitmap);

/// A trait for integral SELinux policy IDs.
pub trait RawId: Sized {
    /// Create from a raw ID value if it is in bounds.
    fn from_raw(id: u32) -> Option<Self>;

    /// Get the raw ID value.
    fn as_raw(&self) -> u32;
}

/// A bitmap set of SELinux policy IDs.
#[derive(Default, Clone)]
pub struct IdSet<T: RawId> {
    inner: Bitmap,
    _data: PhantomData<T>,
}

impl<T: RawId> IdSet<T> {
    /// Create an empty set.
    pub fn new() -> Self {
        Self {
            inner: Bitmap::new(),
            _data: PhantomData,
        }
    }

    /// Add a value to the set. This will panic if C memory allocation fails.
    /// This is a no-op if the value already exists in the set.
    pub fn insert(&mut self, value: T) {
        self.inner.insert(value.as_raw());
    }

    /// Create a iterator that yields all values in the set.
    pub fn iter(&self) -> IdSetIter<'_, T> {
        self.inner.iter().flat_map(T::from_raw)
    }
}

impl<T: RawId> IntoIterator for IdSet<T> {
    type Item = T;

    type IntoIter = IdSetIntoIter<T>;

    /// Create a consuming iterator that yields all values in the set. The set
    /// cannot be used after calling this. Note that memory for consumed values
    /// isn't released until the iterator is dropped.
    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter().flat_map(T::from_raw)
    }
}

impl<'a, T: RawId> IntoIterator for &'a IdSet<T> {
    type Item = T;

    type IntoIter = IdSetIter<'a, T>;

    /// Same as [`IdSet::iter`].
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

type IdSetIter<'a, T> = FlatMap<BitmapIter<'a>, Option<T>, fn(u32) -> Option<T>>;
type IdSetIntoIter<T> = FlatMap<BitmapIntoIter, Option<T>, fn(u32) -> Option<T>>;

macro_rules! define_id_wrapper {
    ($name:ident, $nztype:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(transparent)]
        pub struct $name($nztype);

        impl $name {
            #[allow(dead_code)]
            fn inner(&self) -> $nztype {
                self.0
            }
        }

        impl RawId for $name {
            fn from_raw(id: u32) -> Option<Self> {
                Some(Self($nztype::new(id.try_into().ok()?)?))
            }

            fn as_raw(&self) -> u32 {
                self.inner().get().into()
            }
        }

        impl From<$nztype> for $name {
            fn from(id: $nztype) -> Self {
                Self(id)
            }
        }
    };
}

define_id_wrapper!(RoleId, NonZeroU16);
define_id_wrapper!(TypeId, NonZeroU16);
define_id_wrapper!(ClassId, NonZeroU16);
define_id_wrapper!(PermId, NonZeroU32);

#[inline]
fn xperm_driver(xperm: u16) -> u8 {
    (xperm >> 8) as u8
}

#[inline]
fn xperm_function(xperm: u16) -> u8 {
    (xperm & 0xff) as u8
}

// The xperms permission bit pattern from Rust's perspective, not the hardware
// perspective, is:
//
// [Item 0     ] [Item 1        ] .. [Item 7            ]
// [31 .. 2 1 0] [63 .. 34 33 32] .. [255 .. 226 225 224]

#[inline]
fn xperm_set(data: &mut [u32; 8], bit: u8, value: bool) {
    let item_index = usize::from(bit >> 5);
    let bit_index = u32::from(bit & 0x1f);

    if value {
        data[item_index] |= 1 << bit_index;
    } else {
        data[item_index] &= !(1 << bit_index);
    }
}

#[inline]
fn xperms_get(data: &[u32; 8], bit: u8) -> bool {
    let byte_index = usize::from(bit >> 5);
    let bit_index = u32::from(bit & 0x1f);

    data[byte_index] & (1 << bit_index) != 0
}

/// Sort an merge overlapping inclusive ranges.
fn merge_overlapping<T>(sections: &[RangeInclusive<T>]) -> Vec<RangeInclusive<T>>
where
    T: PrimInt,
{
    let mut sections = sections.to_vec();
    sections.sort_by_key(|r| (*r.start(), *r.end()));

    let mut result = Vec::<RangeInclusive<T>>::new();

    for section in sections {
        if section.start() >= section.end() {
            continue;
        } else if let Some(last) = result.last_mut() {
            if section.start() <= last.end()
                || (*section.start()).checked_sub(last.end()) == Some(T::one())
            {
                *last = *last.start()..=*last.end().max(section.end());
                continue;
            }
        }

        result.push(section);
    }

    result
}

/// The action to take when a rule is matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleAction {
    /// Deny the action and log the denial. This is the default behavior and is
    /// represented in the binary policy as the absence of a rule.
    AuditDeny,
    /// Deny the action silently.
    Deny,
    /// Allow the action, but log it.
    AuditAllow,
    /// Allow the action silently.
    Allow,
}

/// Main type for manipulating a binary SELinux policy.
pub struct PolicyDb(Box<policydb>);

impl PolicyDb {
    /// Parse binary SELinux policy from a reader. If warnings or errors are
    /// emitted, they are written to `messages`. Warnings may be emitted even if
    /// the binary policy is successfully parsed.
    pub fn from_reader(mut reader: impl Read, messages: &mut Vec<String>) -> io::Result<Self> {
        unsafe {
            // Boxed because policydb has self-referential pointers.
            let mut pdb = Box::<policydb>::new(mem::zeroed());

            if policydb_init(pdb.as_mut()) < 0 {
                panic!("Failed to initialize policydb");
            }

            // Just read the whole thing to memory. libsepol's file load feature
            // only supports <stdio.h>'s FILE and policy files are very small,
            // so it's not worth mmap'ing the data.
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;

            let handle = MessageHandle::new();
            let ret = policydb_from_image(
                handle.handle,
                data.as_mut_ptr().cast(),
                data.len(),
                pdb.as_mut(),
            );

            messages.extend(handle.into_vec());

            if ret < 0 {
                // policydb_from_image() calls policydb_destroy() on failure, so
                // there is nothing to clean up.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to parse policydb",
                ));
            }

            Ok(Self(pdb))
        }
    }

    /// Write binary SELinux policy to a writer. This is guaranteed to write the
    /// entire data in a single [`Write::write`] call, which allows this to be
    /// used for loading a policy into the kernel via `/sys/fs/selinux/load`.
    /// If warnings or errors are emitted, they are written to `messages`.
    /// Warnings may be emitted even if the binary policy is successfully
    /// written.
    #[allow(clippy::wrong_self_convention)]
    pub fn to_writer(
        &mut self,
        mut writer: impl Write,
        messages: &mut Vec<String>,
    ) -> io::Result<()> {
        let handle = MessageHandle::new();
        let mut buf = CBuf::new();

        let ret = unsafe {
            policydb_to_image(handle.handle, self.0.as_mut(), &mut buf.data, &mut buf.len)
        };

        messages.extend(handle.into_vec());

        if ret < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to write policydb",
            ));
        }

        let data = unsafe { slice::from_raw_parts(buf.data as *const u8, buf.len) };

        // /sys/fs/selinux/load requires the entire policy to be written in a
        // single write(2) call.
        // See: http://marc.info/?l=selinux&m=141882521027239&w=2
        let n = writer.write(data)?;
        if n != data.len() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }

        Ok(())
    }

    /// SELinux binary policy version number.
    pub fn policy_version(&self) -> u32 {
        self.0.policyvers
    }

    /// Recreate maps like type_val_to_struct. libsepol will handle memory
    /// deallocation for the old maps.
    fn raw_reindex(&mut self) -> io::Result<()> {
        unsafe {
            if policydb_index_decls_wrapper(ptr::null_mut(), self.0.as_mut()) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to reindex decls",
                ));
            }

            if policydb_index_classes(self.0.as_mut()) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to reindex classes",
                ));
            }

            if policydb_index_others(ptr::null_mut(), self.0.as_mut(), 0) != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Failed to reindex other data",
                ));
            }
        }

        Ok(())
    }

    /// Find the role ID for the specified name.
    pub fn get_role_id(&self, name: &str) -> Option<RoleId> {
        let c_name = CString::new(name).ok()?;

        unsafe {
            let role = hashtab_search(self.0.symtab[SYM_ROLES as usize].table, c_name.as_ptr())
                .cast::<role_datum>();

            if role.is_null() {
                None
            } else {
                let id = NonZeroU16::new((*role).s.value as u16)?;
                Some(id.into())
            }
        }
    }

    /// Get the role struct for the specified ID.
    fn get_role(&self, id: RoleId) -> Option<NonNull<role_datum>> {
        if id.as_raw() > self.0.symtab[SYM_ROLES as usize].nprim {
            return None;
        }

        unsafe { NonNull::new(*self.0.role_val_to_struct.add(id.as_raw() as usize - 1)) }
    }

    /// Get the set of all roles.
    pub fn all_roles(&self) -> IdSet<RoleId> {
        let table = self.0.symtab[SYM_ROLES as usize];
        let mut set = IdSet::new();

        for i in 1..=table.nprim {
            let id = NonZeroU16::new(i as u16).unwrap();
            set.insert(id.into());
        }

        set
    }

    /// Find the type or attribute ID for the specified name.
    pub fn get_type_id(&self, name: &str) -> Option<TypeId> {
        let c_name = CString::new(name).ok()?;

        unsafe {
            let r#type = hashtab_search(self.0.symtab[SYM_TYPES as usize].table, c_name.as_ptr())
                .cast::<type_datum>();

            if r#type.is_null() {
                None
            } else {
                let id = NonZeroU16::new((*r#type).s.value as u16)?;
                Some(id.into())
            }
        }
    }

    /// Get the type struct for the specified ID.
    fn get_type(&self, id: TypeId) -> Option<NonNull<type_datum>> {
        if id.as_raw() > self.0.symtab[SYM_TYPES as usize].nprim {
            return None;
        }

        unsafe { NonNull::new(*self.0.type_val_to_struct.add(id.as_raw() as usize - 1)) }
    }

    /// Get the set of all types and attributes.
    pub fn all_types(&self) -> IdSet<TypeId> {
        let table = self.0.symtab[SYM_TYPES as usize];
        let mut set = IdSet::new();

        for i in 1..=table.nprim {
            let id = NonZeroU16::new(i as u16).unwrap();
            set.insert(id.into());
        }

        set
    }

    /// Find the class ID for the specified name.
    pub fn get_class_id(&self, name: &str) -> Option<ClassId> {
        let c_name = CString::new(name).ok()?;

        unsafe {
            let class = hashtab_search(self.0.symtab[SYM_CLASSES as usize].table, c_name.as_ptr())
                .cast::<class_datum>();

            if class.is_null() {
                None
            } else {
                let id = NonZeroU16::new((*class).s.value as u16)?;
                Some(id.into())
            }
        }
    }

    /// Get the class struct for the specified ID.
    fn get_class(&self, id: ClassId) -> Option<NonNull<class_datum>> {
        if id.as_raw() > self.0.symtab[SYM_CLASSES as usize].nprim {
            return None;
        }

        unsafe { NonNull::new(*self.0.class_val_to_struct.add(id.as_raw() as usize - 1)) }
    }

    /// Get the set of all classes.
    pub fn all_classes(&self) -> IdSet<ClassId> {
        let table = self.0.symtab[SYM_CLASSES as usize];
        let mut set = IdSet::new();

        for i in 1..=table.nprim {
            let id = NonZeroU16::new(i as u16).unwrap();
            set.insert(id.into());
        }

        set
    }

    /// Find the permission ID for the specified name within the class.
    pub fn get_perm_id(&self, class_id: ClassId, name: &str) -> Option<PermId> {
        let class = self.get_class(class_id)?;
        let c_name = CString::new(name).ok()?;

        unsafe {
            // Find class-specific permissions first.
            let mut perm =
                hashtab_search((*class.as_ptr()).permissions.table, c_name.as_ptr().cast())
                    .cast::<perm_datum>();

            // Then try common permissions.
            if perm.is_null() && !(*class.as_ptr()).comdatum.is_null() {
                perm = hashtab_search(
                    (*(*class.as_ptr()).comdatum).permissions.table,
                    c_name.as_ptr().cast(),
                )
                .cast::<perm_datum>();
            }

            if perm.is_null() {
                None
            } else {
                let id = NonZeroU32::new((*perm).s.value)?;
                Some(id.into())
            }
        }
    }

    /// Get the permission struct for the specified ID within the class.
    fn get_perm(&self, class_id: ClassId, perm_id: PermId) -> Option<NonNull<perm_datum>> {
        let class = self.get_class(class_id)?;

        unsafe {
            let specific = (*class.as_ptr()).permissions.table;
            let common = if !(*class.as_ptr()).comdatum.is_null() {
                (*(*class.as_ptr()).comdatum).permissions.table
            } else {
                ptr::null_mut()
            };

            for table in [specific, common] {
                if table.is_null() {
                    continue;
                }

                for bucket in 0..(*table).size {
                    let mut cur = *(*table).htable.add(bucket as usize);

                    while !cur.is_null() {
                        let perm = (*cur).datum.cast::<perm_datum>();

                        if (*perm).s.value == perm_id.as_raw() {
                            return NonNull::new(perm);
                        }

                        cur = (*cur).next;
                    }
                }
            }

            None
        }
    }

    /// Get the set of all permissions within the class.
    pub fn all_perms(&self, class_id: ClassId) -> IdSet<PermId> {
        let mut set = IdSet::new();

        let Some(class) = self.get_class(class_id) else {
            panic!("{class_id:?} out of bounds");
        };

        unsafe {
            let specific = (*class.as_ptr()).permissions.table;
            let common = if !(*class.as_ptr()).comdatum.is_null() {
                (*(*class.as_ptr()).comdatum).permissions.table
            } else {
                ptr::null_mut()
            };

            for table in [specific, common] {
                if table.is_null() {
                    continue;
                }

                for bucket in 0..(*table).size {
                    let mut cur = *(*table).htable.add(bucket as usize);

                    while !cur.is_null() {
                        let perm = (*cur).datum.cast::<perm_datum>();

                        let id = NonZeroU32::new((*perm).s.value).unwrap();
                        set.insert(id.into());

                        cur = (*cur).next;
                    }
                }
            }
        }

        set
    }

    /// Create a new type with the specified name. If `attr` is true, then an
    /// attribute is created instead.
    pub fn create_type(&mut self, name: &str, attr: bool) -> io::Result<(TypeId, bool)> {
        if let Some(type_id) = self.get_type_id(name) {
            return Ok((type_id, false));
        }

        unsafe {
            let name_c = CString::new(name)?;

            // symtab_insert will take ownership of these allocations
            let name_dup = strdup(name_c.as_ptr());
            if name_dup.is_null() {
                panic!("Failed to allocate name");
            }

            let new_type: *mut type_datum = malloc(mem::size_of::<type_datum>()).cast();
            if new_type.is_null() {
                free(name_dup.cast());
                panic!("Failed to allocate type struct");
            }

            type_datum_init(new_type);
            (*new_type).primary = 1;
            (*new_type).flavor = if attr { TYPE_ATTRIB } else { TYPE_TYPE };

            // New value for the type.
            let mut type_val = 0u32;

            // Add type declaration to symbol table.
            if symtab_insert(
                self.0.as_mut(),
                SYM_TYPES,
                name_dup,
                new_type.cast(),
                SCOPE_DECL,
                1,
                &mut type_val,
            ) != 0
            {
                // Policy file is broken.
                free(name_dup.cast());
                free(new_type.cast());
                panic!("Failed to insert type {name} into symbol table");
            }

            (*new_type).s.value = type_val;

            if ebitmap_set_bit(
                &mut (*(*self.0.global).branch_list).declared.scope[SYM_TYPES as usize],
                type_val - 1,
                1,
            ) != 0
            {
                panic!("Failed to insert type {name} into symbol table");
            }

            // Reallocate type-attribute maps for the new type
            // (see: policydb_read() in policydb.c)
            let new_type_attr_map = reallocarray(
                self.0.type_attr_map.cast(),
                self.0.symtab[SYM_TYPES as usize].nprim as usize,
                mem::size_of::<ebitmap>(),
            );
            if new_type_attr_map.is_null() {
                panic!("Failed to reallocate type->attr map");
            }
            self.0.type_attr_map = new_type_attr_map.cast();

            let new_attr_type_map = reallocarray(
                self.0.attr_type_map.cast(),
                self.0.symtab[SYM_TYPES as usize].nprim as usize,
                mem::size_of::<ebitmap>(),
            );
            if new_attr_type_map.is_null() {
                panic!("Failed to reallocate attr->type map");
            }
            self.0.attr_type_map = new_attr_type_map.cast();

            // Initialize newly-allocated bitmap.
            ebitmap_init_wrapper(self.0.type_attr_map.add((type_val - 1) as usize));
            ebitmap_init_wrapper(self.0.attr_type_map.add((type_val - 1) as usize));

            // Handle degenerate case.
            if ebitmap_set_bit(
                self.0.type_attr_map.add((type_val - 1) as usize),
                type_val - 1,
                1,
            ) < 0
            {
                panic!("Failed to add type {name} to type<->attr map");
            }

            self.raw_reindex()?;

            let id = NonZeroU16::new(type_val as u16).unwrap();
            Ok((id.into(), true))
        }
    }

    /// Add a type to a role. Returns true if a change was made or false if the
    /// type was already added to the role.
    pub fn add_to_role(&mut self, role_id: RoleId, type_id: TypeId) -> io::Result<bool> {
        unsafe {
            if self.get_type(type_id).is_none() {
                panic!("{type_id:?} out of bounds");
            }

            let Some(role) = self.get_role(role_id) else {
                panic!("{role_id:?} out of bounds");
            };

            if ebitmap_get_bit(&(*role.as_ptr()).types.types, type_id.as_raw() - 1) != 0 {
                return Ok(false);
            }

            if ebitmap_set_bit(&mut (*role.as_ptr()).types.types, type_id.as_raw() - 1, 1) < 0 {
                panic!("Failed to update role types");
            }

            if ebitmap_set_bit(&mut (*role.as_ptr()).types.negset, type_id.as_raw() - 1, 0) < 0 {
                panic!("Failed to update role negset");
            }

            self.raw_reindex()?;

            Ok(true)
        }
    }

    /// Copy the roles from the source type to the target type. Returns true if
    /// a change was made or false if the target type was already in the roles
    /// that the source type was in.
    pub fn copy_roles(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
    ) -> io::Result<bool> {
        let mut changed = false;

        for i in 1..=self.0.symtab[SYM_ROLES as usize].nprim {
            let role_id = RoleId::from(NonZeroU16::new(i as u16).unwrap());

            let Some(role) = self.get_role(role_id) else {
                panic!("{role_id:?} out of bounds");
            };

            if unsafe {
                ebitmap_get_bit(&(*role.as_ptr()).types.types, source_type_id.as_raw() - 1)
            } == 0
            {
                continue;
            }

            changed |= self.add_to_role(role_id, target_type_id)?;
        }

        Ok(changed)
    }

    /// Set or remove an attribute on a type. Returns true if a change was made
    /// or false if the type already had the attribute set/removed.
    pub fn set_attribute(
        &mut self,
        type_id: TypeId,
        attr_id: TypeId,
        value: bool,
    ) -> io::Result<bool> {
        unsafe {
            if let Some(s) = self.get_type(type_id) {
                let flavor = (*s.as_ptr()).flavor;
                if flavor != TYPE_TYPE {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{type_id:?} is not a type: {flavor}"),
                    ));
                }
            } else {
                panic!("{type_id:?} out of bounds");
            }

            if let Some(s) = self.get_type(attr_id) {
                let flavor = (*s.as_ptr()).flavor;
                if flavor != TYPE_ATTRIB {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("{attr_id:?} is not a attr: {flavor}"),
                    ));
                }
            } else {
                panic!("{attr_id:?} out of bounds");
            }

            let mut ret1 = ebitmap_get_bit(
                self.0.type_attr_map.add(type_id.as_raw() as usize - 1),
                attr_id.as_raw() - 1,
            );
            let mut ret2 = ebitmap_get_bit(
                self.0.attr_type_map.add(attr_id.as_raw() as usize - 1),
                type_id.as_raw() - 1,
            );

            if ret1 != ret2 {
                panic!("Inconsistent type<->attr maps");
            }

            let mut changed = false;

            // Update type-attribute maps.

            if (ret1 != 0) != value {
                ret1 = ebitmap_set_bit(
                    self.0.type_attr_map.add(type_id.as_raw() as usize - 1),
                    attr_id.as_raw() - 1,
                    value.into(),
                );
                ret2 = ebitmap_set_bit(
                    self.0.attr_type_map.add(attr_id.as_raw() as usize - 1),
                    type_id.as_raw() - 1,
                    value.into(),
                );

                if ret1 < 0 || ret2 < 0 {
                    panic!("Failed to update type<->attr maps");
                }

                changed = true;
            }

            // As of 5.0-rc6, the kernel doesn't use expr->type_names in
            // constraint_expr_eval(), even if pdb->policyvers >=
            // POLICYDB_VERSION_CONSTRAINT_NAMES. This loop will check every
            // constraint and toggle the bit corresponding to `type_val` in
            // expr->names if the bit corresponding to `attr_val` is toggled in
            // expr->type_names->types. Note that this only works if the source
            // policy version is new enough. Older policies do not retain
            // attribute information in the constraints.
            for class_val in 1..=self.0.symtab[SYM_CLASSES as usize].nprim {
                let class = *self.0.class_val_to_struct.add((class_val - 1) as usize);

                let mut node = (*class).constraints;
                while !node.is_null() {
                    let mut expr = (*node).expr;
                    while !expr.is_null() {
                        if (*expr).expr_type == CEXPR_NAMES
                            && (*expr).attr & CEXPR_TYPE != 0
                            && ebitmap_get_bit(&(*(*expr).type_names).types, attr_id.as_raw() - 1)
                                != 0
                        {
                            if ebitmap_set_bit(
                                &mut (*expr).names,
                                type_id.as_raw() - 1,
                                value.into(),
                            ) < 0
                            {
                                panic!("Failed to update MLS constraints");
                            }

                            changed = true;
                        }

                        expr = (*expr).next;
                    }

                    node = (*node).next;
                }
            }

            Ok(changed)
        }
    }

    /// Copy the attributes from the source type to the target type. Returns
    /// true if a change was made or false if the target type already had all
    /// attributes that the source type had.
    pub fn copy_attributes(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
    ) -> io::Result<bool> {
        let attrs_0_indexed = unsafe {
            BitmapRef::from_ptr(
                self.0
                    .type_attr_map
                    .add(source_type_id.as_raw() as usize - 1),
            )
        };

        let mut changed = false;

        for raw_id in attrs_0_indexed {
            let attr_id = TypeId::from(NonZeroU16::new(raw_id as u16 + 1).unwrap());
            if attr_id == source_type_id {
                continue;
            }

            changed |= self.set_attribute(target_type_id, attr_id, true)?;
        }

        Ok(changed)
    }

    /// Copy the MLS constraints that reference the source type to also
    /// reference the target type. Returns true if a change was made or false
    /// if all MLS constraints that reference the source type already reference
    /// the target type.
    pub fn copy_constraints(&mut self, source_type_id: TypeId, target_type_id: TypeId) -> bool {
        let mut changed = false;

        unsafe {
            for class_val in 1..=self.0.symtab[SYM_CLASSES as usize].nprim {
                let class = *self.0.class_val_to_struct.add((class_val - 1) as usize);

                let mut node = (*class).constraints;
                while !node.is_null() {
                    let mut expr = (*node).expr;
                    while !expr.is_null() {
                        if (*expr).expr_type == CEXPR_NAMES
                            && (*expr).attr & CEXPR_TYPE != 0
                            && ebitmap_get_bit(&(*expr).names, source_type_id.as_raw() - 1) != 0
                        {
                            if ebitmap_set_bit(&mut (*expr).names, target_type_id.as_raw() - 1, 1)
                                < 0
                            {
                                panic!("Failed to update MLS constraints");
                            }

                            changed = true;
                        }

                        expr = (*expr).next;
                    }

                    node = (*node).next;
                }
            }
        }

        changed
    }

    /// Set the permissive bit on a type. Returns true if a change was made or
    /// false if the type already had the permissive bit set appropriately.
    pub fn set_permissive(&mut self, type_id: TypeId, permissive: bool) -> bool {
        unsafe {
            if self.get_type(type_id).is_none() {
                panic!("{type_id:?} out of bounds");
            }

            let ret = ebitmap_get_bit(&self.0.permissive_map, type_id.as_raw());
            if (ret != 0) == permissive {
                return false;
            }

            if ebitmap_set_bit(
                &mut self.0.permissive_map,
                type_id.as_raw(),
                permissive as i32,
            ) < 0
            {
                panic!("Failed to set permissive bit");
            }

            true
        }
    }

    /// The default value for [`avtab_datum::data`] based on
    /// [`avtab_key::specified`].
    fn default_node_data(specified: u16) -> u32 {
        if u32::from(specified) & AVTAB_AUDITDENY != 0 {
            !0
        } else {
            0
        }
    }

    /// Find or create an avtab node. This does not take ownership of either
    /// input parameter. Returns the pointer to the avtab struct and whether it
    /// was newly created.
    unsafe fn find_or_create_avtab_node(
        &mut self,
        key: *mut avtab_key,
        xperms: *mut avtab_extended_perms,
    ) -> (avtab_ptr_t, bool) {
        let mut node = avtab_search_node(&mut self.0.te_avtab, key);

        if u32::from((*key).specified) & AVTAB_XPERMS != 0 {
            let mut found = false;

            while !node.is_null() {
                let node_xperms = (*node).datum.xperms;

                if (*node_xperms).specified == (*xperms).specified
                    && (*node_xperms).driver == (*xperms).driver
                {
                    found = true;
                    break;
                }

                node = avtab_search_node_next(node, (*key).specified.into());
            }

            if !found {
                node = ptr::null_mut();
            }
        }

        let mut created = false;

        if node.is_null() {
            // avtab makes a copy of all data passed to it on insert.
            let mut datum = avtab_datum {
                data: Self::default_node_data((*key).specified),
                xperms,
            };

            node = avtab_insert_nonunique(&mut self.0.te_avtab, key, &mut datum);
            if node.is_null() {
                panic!("Failed to insert avtab entry");
            }

            created = true;
        }

        (node, created)
    }

    /// Remove an avtab node. Since the input is a pointer to a node, this will
    /// panic if the node is not found in the policy.
    unsafe fn remove_avtab_node(&mut self, node: *mut avtab_node) {
        let hash = avtab_hash_wrapper(&mut (*node).key, self.0.te_avtab.mask);

        let bucket = self.0.te_avtab.htable.add(hash as usize);
        let mut prev = ptr::null_mut();
        let mut cur = *bucket;

        while !cur.is_null() {
            if cur == node {
                break;
            }
            prev = cur;
            cur = (*cur).next;
        }

        if cur.is_null() {
            // Data structures are corrupt.
            panic!("Node does not exist in avtab");
        }

        if !prev.is_null() {
            (*prev).next = (*node).next;
        } else {
            *bucket = (*node).next;
        }

        self.0.te_avtab.nel -= 1;

        free((*node).datum.xperms.cast());
        free(node.cast());
    }

    /// Set the raw permission bit for a non-xperm rule. Note that this does not
    /// automatically invert the bit for [`AVTAB_AUDITDENY`].
    fn set_rule_raw(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
        class_id: ClassId,
        perm_id: PermId,
        specified: u16,
        value: bool,
    ) -> bool {
        if self.get_type(source_type_id).is_none() {
            panic!("{source_type_id:?} out of bounds");
        } else if self.get_type(target_type_id).is_none() {
            panic!("{target_type_id:?} out of bounds");
        } else if self.get_class(class_id).is_none() {
            panic!("{class_id:?} out of bounds");
        } else if self.get_perm(class_id, perm_id).is_none() {
            panic!("{class_id:?} -> {perm_id:?} out of bounds");
        }

        let mut key = avtab_key {
            source_type: source_type_id.inner().get(),
            target_type: target_type_id.inner().get(),
            target_class: class_id.inner().get(),
            specified,
        };

        unsafe {
            let (node, mut created) = self.find_or_create_avtab_node(&mut key, ptr::null_mut());

            let old_data = (*node).datum.data;

            if value {
                (*node).datum.data |= 1 << (perm_id.as_raw() - 1);
            } else {
                (*node).datum.data &= !(1 << (perm_id.as_raw() - 1));
            }

            created |= (*node).datum.data != old_data;

            if (*node).datum.data == Self::default_node_data(specified) {
                self.remove_avtab_node(node);
            }

            created
        }
    }

    /// Set the action to take when the rule is matched. A rule only exists in
    /// the policy if the action is not [`RuleAction::AuditDeny`].
    pub fn set_rule(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
        class_id: ClassId,
        perm_id: PermId,
        action: RuleAction,
    ) -> bool {
        let (specified, insert) = match action {
            RuleAction::AuditDeny => (AVTAB_ALLOWED, false),
            RuleAction::Deny => (AVTAB_AUDITDENY, false),
            RuleAction::AuditAllow => (AVTAB_AUDITALLOW, true),
            RuleAction::Allow => (AVTAB_ALLOWED, true),
        };

        // Add to the desired table.
        let mut changed = self.set_rule_raw(
            source_type_id,
            target_type_id,
            class_id,
            perm_id,
            specified as u16,
            insert,
        );

        // Remove from the remaining tables to guarantee consistency.
        for remove_specified in [AVTAB_ALLOWED, AVTAB_AUDITALLOW, AVTAB_AUDITDENY] {
            if remove_specified != specified {
                changed |= self.set_rule_raw(
                    source_type_id,
                    target_type_id,
                    class_id,
                    perm_id,
                    remove_specified as u16,
                    // 0 is the default state in every table besides auditdeny.
                    remove_specified == AVTAB_AUDITDENY,
                );
            }
        }

        changed
    }

    /// Set or remove the ranges from an xperm rule in the specified table.
    fn set_xperm_rule_raw(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
        class_id: ClassId,
        xperm_ranges: &[RangeInclusive<u16>],
        specified: u16,
        value: bool,
    ) -> io::Result<bool> {
        if self.get_type(source_type_id).is_none() {
            panic!("{source_type_id:?} out of bounds");
        } else if self.get_type(target_type_id).is_none() {
            panic!("{target_type_id:?} out of bounds");
        } else if self.get_class(class_id).is_none() {
            panic!("{class_id:?} out of bounds");
        }

        let mut key = avtab_key {
            source_type: source_type_id.inner().get(),
            target_type: target_type_id.inner().get(),
            target_class: class_id.inner().get(),
            specified,
        };

        // The driver node's permission bits indicate whether all of each
        // driver's functions are allowed. A function node's permissions bits
        // indicate whether a specific driver's function is allowed. Linux does
        // an exhaustive search over every matching node, so a 1 bit in the
        // driver node dominates whatever is in the corresponding function node.
        let mut driver_node = ptr::null_mut::<avtab_node>();
        let mut function_nodes = [ptr::null_mut::<avtab_node>(); 256];

        // Look up all the nodes beforehand to avoid repeatedly performing O(n)
        // lookups in the list of nodes matching the key. Although Linux allows
        // duplicate driver and function nodes, we don't allow it since no real
        // policy file has duplicates and it would prevent this optimization.
        unsafe {
            let mut node = avtab_search_node(&mut self.0.te_avtab, &mut key);

            while !node.is_null() {
                let xperms = (*node).datum.xperms;

                match u32::from((*xperms).specified) {
                    AVTAB_XPERMS_IOCTLDRIVER => {
                        if !driver_node.is_null() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Duplicate function node",
                            ));
                        }

                        driver_node = node
                    }
                    AVTAB_XPERMS_IOCTLFUNCTION => {
                        let f = &mut function_nodes[usize::from((*xperms).driver)];
                        if !(*f).is_null() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("Duplicate function node for driver: {}", (*xperms).driver),
                            ));
                        }

                        *f = node;
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Unknown xperms specified value: {}", (*xperms).specified),
                        ))
                    }
                }

                node = avtab_search_node_next(node, key.specified.into());
            }
        }

        let ranges = merge_overlapping(xperm_ranges);

        let mut changed = false;

        unsafe {
            for range in ranges {
                for driver in xperm_driver(*range.start())..=xperm_driver(*range.end()) {
                    let xperm_min = u16::from(driver) << 8;
                    let xperm_max = xperm_min | 0xff;
                    let func_start = xperm_function((*range.start()).clamp(xperm_min, xperm_max));
                    let func_end = xperm_function((*range.end()).clamp(xperm_min, xperm_max));

                    if func_start == func_end {
                        continue;
                    }

                    // Fill out what is currently enabled in the policy.

                    let mut current = [0u32; 8];

                    if !driver_node.is_null() {
                        let perms = &(*(*driver_node).datum.xperms).perms;
                        if xperms_get(perms, driver) {
                            current.fill(u32::MAX);
                        }
                    }

                    let function_node = &mut function_nodes[usize::from(driver)];

                    if !(*function_node).is_null() {
                        let perms = &(*(**function_node).datum.xperms).perms;
                        for (d, p) in current.iter_mut().zip(perms) {
                            *d |= *p;
                        }
                    }

                    // Then, apply the specified changes. We avoid bit-by-bit
                    // comparisons where possible because it slows down the
                    // process significantly.

                    let mut desired = current;

                    for i in 0..desired.len() {
                        let chunk_min = i as u8 * 32;
                        let chunk_max = chunk_min + 31;
                        let chunk_start = func_start.clamp(chunk_min, chunk_max);
                        let chunk_end = func_end.clamp(chunk_min, chunk_max);

                        if chunk_start == chunk_min && chunk_end == chunk_max {
                            desired[i] = if value { u32::MAX } else { u32::MIN };
                        } else {
                            for function in chunk_start..=chunk_end {
                                xperm_set(&mut desired, function, value);
                            }
                        }
                    }

                    if desired != current {
                        changed = true;
                    } else {
                        continue;
                    }

                    let all_filled = desired.iter().all(|d| *d == u32::MAX);
                    let all_empty = desired.iter().all(|d| *d == u32::MIN);

                    if all_filled || all_empty {
                        // In the two extreme cases, the permissions can be
                        // represented with a single bit in the driver node. The
                        // function node, if it exists, can be deleted.

                        if !(*function_node).is_null() {
                            self.remove_avtab_node(*function_node);
                            *function_node = ptr::null_mut();
                        }

                        if driver_node.is_null() {
                            if all_empty {
                                // No need to add a driver node if we're
                                // removing all permissions anyway.
                                continue;
                            }

                            let mut xperms = avtab_extended_perms {
                                specified: AVTAB_XPERMS_IOCTLDRIVER as u8,
                                driver: 0,
                                perms: Default::default(),
                            };

                            let (node, created) =
                                self.find_or_create_avtab_node(&mut key, &mut xperms);
                            assert!(created, "Duplicate driver node");

                            driver_node = node;
                        }

                        let perms = &mut (*(*driver_node).datum.xperms).perms;
                        xperm_set(perms, driver, all_filled);
                    } else {
                        // Otherwise, the driver node is insufficient and we
                        // need a function node to represent the granular
                        // permissions.

                        if !driver_node.is_null() {
                            // Ensure we aren't granting all permissions.
                            let perms = &mut (*(*driver_node).datum.xperms).perms;
                            xperm_set(perms, driver, false);
                        }

                        if !(*function_node).is_null() {
                            let perms = &mut (*(**function_node).datum.xperms).perms;
                            *perms = desired;
                        } else {
                            let mut xperms = avtab_extended_perms {
                                specified: AVTAB_XPERMS_IOCTLFUNCTION as u8,
                                driver,
                                perms: desired,
                            };

                            let (node, created) =
                                self.find_or_create_avtab_node(&mut key, &mut xperms);
                            assert!(created, "Duplicate function node");

                            *function_node = node;
                        }
                    }
                }
            }
        }

        Ok(changed)
    }

    /// Set the action to take when the xperm rule is matched. A rule only
    /// exists in the policy if the action is not [`RuleAction::AuditDeny`].
    pub fn set_xperm_rule(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
        class_id: ClassId,
        xperm_ranges: &[RangeInclusive<u16>],
        action: RuleAction,
    ) -> io::Result<bool> {
        let (specified, insert) = match action {
            RuleAction::AuditDeny => (AVTAB_XPERMS_ALLOWED, false),
            RuleAction::Deny => (AVTAB_XPERMS_DONTAUDIT, true),
            RuleAction::AuditAllow => (AVTAB_XPERMS_AUDITALLOW, true),
            RuleAction::Allow => (AVTAB_XPERMS_ALLOWED, true),
        };

        // Add to the desired table.
        let mut changed = self.set_xperm_rule_raw(
            source_type_id,
            target_type_id,
            class_id,
            xperm_ranges,
            specified as u16,
            insert,
        )?;

        // Remove from the remaining tables to guarantee consistency.
        for remove_specified in [
            AVTAB_XPERMS_ALLOWED,
            AVTAB_XPERMS_AUDITALLOW,
            AVTAB_XPERMS_DONTAUDIT,
        ] {
            if remove_specified != specified {
                changed |= self.set_xperm_rule_raw(
                    source_type_id,
                    target_type_id,
                    class_id,
                    xperm_ranges,
                    remove_specified as u16,
                    false,
                )?;
            }
        }

        Ok(changed)
    }

    /// Set or remove a type transition rule. Returns true if a change was made
    /// or false if the rule was already set appropriately.
    pub fn set_type_trans(
        &mut self,
        source_type_id: TypeId,
        target_type_id: TypeId,
        class_id: ClassId,
        default_type_id: Option<TypeId>,
    ) -> bool {
        if self.get_type(source_type_id).is_none() {
            panic!("{source_type_id:?} out of bounds");
        } else if self.get_type(target_type_id).is_none() {
            panic!("{target_type_id:?} out of bounds");
        } else if self.get_class(class_id).is_none() {
            panic!("{class_id:?} out of bounds");
        } else if default_type_id.and_then(|t| self.get_type(t)).is_none() {
            panic!("{default_type_id:?} out of bounds");
        }

        let mut key = avtab_key {
            source_type: source_type_id.inner().get(),
            target_type: target_type_id.inner().get(),
            target_class: class_id.inner().get(),
            specified: AVTAB_TRANSITION as u16,
        };

        unsafe {
            let node = avtab_search_node(&mut self.0.te_avtab, &mut key);

            #[allow(clippy::collapsible_else_if)]
            if let Some(default_type_id) = default_type_id {
                if node.is_null() {
                    let mut datum_new = avtab_datum {
                        data: default_type_id.as_raw(),
                        xperms: ptr::null_mut(),
                    };

                    if avtab_insert(&mut self.0.te_avtab, &mut key, &mut datum_new) != 0 {
                        panic!("Failed to insert avtab entry");
                    }

                    true
                } else {
                    let old_data = (*node).datum.data;

                    (*node).datum.data = default_type_id.as_raw();

                    (*node).datum.data != old_data
                }
            } else {
                if node.is_null() {
                    false
                } else {
                    self.remove_avtab_node(node);
                    true
                }
            }
        }
    }

    /// Remove all dontaudit and dontauditxperm rules. This is primarily useful
    /// for troubleshooting and may result in significant spam in the audit
    /// logs.
    pub fn strip_no_audit(&mut self) -> bool {
        unsafe {
            let mut changed = false;

            for i in 0..self.0.te_avtab.nslot {
                let mut cur = *self.0.te_avtab.htable.add(i as usize);
                while !cur.is_null() {
                    if (*cur).key.specified & (AVTAB_AUDITDENY | AVTAB_XPERMS_DONTAUDIT) as u16 != 0
                    {
                        let next = (*cur).next;
                        self.remove_avtab_node(cur);
                        changed = true;
                        cur = next;
                    } else {
                        cur = (*cur).next;
                    }
                }
            }

            changed
        }
    }

    /// Copy avtab rules. For each rule, `func` will be called. If it returns a
    /// new tuple of source type, target type, and class, then the rule will be
    /// copied to that key. If the new key already exists, then the rules are
    /// merged. Returns whether any changes were made.
    #[allow(clippy::type_complexity)]
    pub fn copy_avtab_rules(
        &mut self,
        func: Box<dyn Fn(TypeId, TypeId, ClassId) -> Option<(TypeId, TypeId, ClassId)>>,
    ) -> io::Result<bool> {
        unsafe {
            let mut to_add = vec![];

            // Gather rules to copy.
            for i in 0..self.0.te_avtab.nslot {
                let mut cur = *self.0.te_avtab.htable.add(i as usize);

                while !cur.is_null() {
                    if let Some((source_type_id, target_type_id, class_id)) = func(
                        TypeId::from(NonZeroU16::new((*cur).key.source_type).unwrap()),
                        TypeId::from(NonZeroU16::new((*cur).key.target_type).unwrap()),
                        ClassId::from(NonZeroU16::new((*cur).key.target_class).unwrap()),
                    ) {
                        let new_key = avtab_key {
                            source_type: source_type_id.inner().get(),
                            target_type: target_type_id.inner().get(),
                            target_class: class_id.inner().get(),
                            ..(*cur).key
                        };

                        to_add.push((new_key, (*cur).datum));
                    }

                    cur = (*cur).next;
                }
            }

            let mut changed = false;

            for (mut key, datum) in to_add {
                let (node, created) = self.find_or_create_avtab_node(&mut key, datum.xperms);
                if node.is_null() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "avtab key not found: {:?}, {:?}, {:?}",
                            TypeId::from(NonZeroU16::new(key.source_type).unwrap()),
                            TypeId::from(NonZeroU16::new(key.target_type).unwrap()),
                            ClassId::from(NonZeroU16::new(key.target_class).unwrap()),
                        ),
                    ));
                }

                changed |= created;

                let specified = u32::from(key.specified);

                if specified & AVTAB_XPERMS != 0 {
                    let source_xperms = &(*datum.xperms).perms;
                    let target_xperms = &mut (*(*node).datum.xperms).perms;

                    for (s, t) in source_xperms.iter().zip(target_xperms.iter_mut()) {
                        let old = *t;
                        *t |= s;
                        changed |= *t != old;
                    }
                }

                let old = (*node).datum.data;

                if specified == AVTAB_AUDITDENY {
                    (*node).datum.data &= datum.data;
                } else {
                    // For AVTAB_XPERMS, data is used for neverallow rules.
                    (*node).datum.data |= datum.data;
                }

                changed |= (*node).datum.data != old;
            }

            Ok(changed)
        }
    }
}

impl Drop for PolicyDb {
    fn drop(&mut self) {
        unsafe { policydb_destroy(self.0.as_mut()) }
    }
}
