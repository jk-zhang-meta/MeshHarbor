// SPDX-License-Identifier: MPL-2.0
//! MeshHarbor — the SFTP server a device runs when its OS has none.
//!
//! MeshHarbor SSH serves the `sftp` subsystem by handing the channel to
//! OpenSSH's own `sftp-server`, started as the session's account
//! (`ssh.rs`, `docs/meshharbor-ssh.md` § File transfer). A minimal Debian,
//! Ubuntu or Fedora image ships no `sftp-server` at all, and modern `scp`
//! speaks SFTP, so on those devices every `scp` and `sftp` failed — with a bare
//! "Connection closed" (field, 2026-11-20: three of the four WSL distros).
//!
//! This is the fallback, shipped inside the daemon's own binary:
//! `meshharbord sftp-server` speaks SFTP v3 on stdin/stdout. The daemon starts
//! it **exactly where it would start OpenSSH's**: a child process, under the
//! session's account (`apply_run_as_at_home` on Unix; the console user's token
//! on Windows), in that account's home. So the privilege story is unchanged —
//! every open, read and write is the account's own, checked by the kernel; this
//! process never runs as root/SYSTEM on a session's behalf unless the session
//! itself is root/SYSTEM, which is what OpenSSH's server would have been too.
//!
//! The OS's `sftp-server` stays first wherever it exists: it is the reference
//! implementation, and it is what every device served before this.
//!
//! Paths: Unix paths pass through. On Windows a path is `/C:/dir/file` (the
//! form OpenSSH for Windows uses, and what `realpath` answers), `C:/dir/file`
//! or relative to the home directory; `/` lists the drives.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Packet, Status, StatusCode, Version,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

/// The hidden subcommand: `meshharbord sftp-server`, with nothing after it.
pub const SUBCOMMAND: &str = "sftp-server";

/// OpenSSH's extension for `~` paths. Modern `scp` needs it for `host:~/x`.
const EXPAND_PATH: &str = "expand-path@openssh.com";

/// The most one READ answers. OpenSSH asks for 32 KiB; a client that asks
/// for more gets a short read, which SFTP allows.
const MAX_READ: u32 = 256 * 1024;

/// Open handles one session may hold: a misbehaving client cannot make this
/// process hold every file descriptor it can get.
const MAX_HANDLES: usize = 1024;

/// Entries per READDIR answer.
const READDIR_BATCH: usize = 128;

/// `true` when argv is exactly `<exe> sftp-server`. Read off argv, not through
/// clap: none of the daemon's startup belongs to this process.
pub fn requested() -> bool {
    let mut args = std::env::args_os().skip(1);
    args.next().as_deref() == Some(OsStr::new(SUBCOMMAND)) && args.next().is_none()
}

/// Serve SFTP on stdin/stdout and exit, when [`requested`]. Nothing is
/// written anywhere else: stdout is the protocol, and no logger is installed,
/// so no line can corrupt it.
pub fn exit_if_requested() {
    if !requested() {
        return;
    }
    let code = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => {
            rt.block_on(serve(tokio::io::stdin(), tokio::io::stdout()));
            0
        }
        Err(e) => {
            eprintln!("meshharbord sftp-server: {e}");
            1
        }
    };
    // Exit rather than return: the stdin reader is a blocking thread that a
    // runtime shutdown would wait on.
    std::process::exit(code);
}

/// Serve one SFTP session over `input`/`output` until the client goes away.
pub async fn serve<R, W>(input: R, output: W)
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let stream = Stdio {
        input,
        output,
        done: Some(done_tx),
    };
    // `run` spawns the session and returns; the stream is dropped when the
    // session ends (the client closed its side), which is what `done` reports.
    russh_sftp::server::run(stream, Fs::new()).await;
    let _ = done_rx.await;
}

/// stdin + stdout as one stream, reporting its own drop.
struct Stdio<R, W> {
    input: R,
    output: W,
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl<R, W> Drop for Stdio<R, W> {
    fn drop(&mut self) {
        if let Some(done) = self.done.take() {
            let _ = done.send(());
        }
    }
}

impl<R: tokio::io::AsyncRead + Unpin, W: Unpin> tokio::io::AsyncRead for Stdio<R, W> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.input).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Stdio<R, W> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.output).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.output).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.output).poll_shutdown(cx)
    }
}

enum Entry {
    File(tokio::fs::File),
    /// A directory listing, served in batches; empty once it has all gone out.
    Dir(Vec<File>),
}

struct Fs {
    handles: HashMap<String, Entry>,
    next: u64,
}

impl Fs {
    fn new() -> Self {
        Self {
            handles: HashMap::new(),
            next: 0,
        }
    }

    fn insert(&mut self, entry: Entry) -> Result<String, StatusCode> {
        if self.handles.len() >= MAX_HANDLES {
            return Err(StatusCode::Failure);
        }
        self.next += 1;
        let handle = self.next.to_string();
        self.handles.insert(handle.clone(), entry);
        Ok(handle)
    }

    fn file(&mut self, handle: &str) -> Result<&mut tokio::fs::File, StatusCode> {
        match self.handles.get_mut(handle) {
            Some(Entry::File(f)) => Ok(f),
            _ => Err(StatusCode::Failure),
        }
    }
}

fn ok(id: u32) -> Status {
    Status {
        id,
        status_code: StatusCode::Ok,
        error_message: "Ok".to_string(),
        language_tag: "en-US".to_string(),
    }
}

fn status_of(e: std::io::Error) -> StatusCode {
    match e.kind() {
        std::io::ErrorKind::NotFound => StatusCode::NoSuchFile,
        std::io::ErrorKind::PermissionDenied => StatusCode::PermissionDenied,
        std::io::ErrorKind::UnexpectedEof => StatusCode::Eof,
        _ => StatusCode::Failure,
    }
}

/// The attributes of `meta`, with the file type right for a symlink (the
/// crate's conversion calls everything that is not a directory "regular").
fn attrs_of(meta: &std::fs::Metadata) -> FileAttributes {
    let mut attrs = FileAttributes::from(meta);
    if meta.file_type().is_symlink() {
        attrs.set_regular(false);
        attrs.set_symlink(true);
    }
    attrs
}

/// The directory attributes `/` answers on Windows, where it is the drive list.
#[cfg(windows)]
fn root_attrs() -> FileAttributes {
    let mut attrs = FileAttributes::empty();
    attrs.permissions = Some(0o555);
    attrs.set_dir(true);
    attrs
}

/// What a client's path names on this machine.
enum Target {
    Path(PathBuf),
    /// Windows' `/`: the drive list.
    #[cfg_attr(not(windows), allow(dead_code))]
    Drives,
}

#[cfg(not(windows))]
fn target(path: &str) -> Target {
    Target::Path(if path.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(path)
    })
}

#[cfg(windows)]
fn target(path: &str) -> Target {
    let p = path.replace('\\', "/");
    if p == "/" {
        return Target::Drives;
    }
    // `/C:/x` → `C:/x`; `/C:` → `C:/`.
    let p = match p.as_bytes() {
        [b'/', d, b':', ..] if d.is_ascii_alphabetic() => p[1..].to_string(),
        _ => p,
    };
    let p = if p.len() == 2 && p.ends_with(':') {
        format!("{p}/")
    } else {
        p
    };
    if p.is_empty() {
        return Target::Path(PathBuf::from("."));
    }
    Target::Path(PathBuf::from(p.replace('/', "\\")))
}

fn path_of(path: &str) -> Result<PathBuf, StatusCode> {
    match target(path) {
        Target::Path(p) => Ok(p),
        Target::Drives => Err(StatusCode::PermissionDenied),
    }
}

/// A path as a client should see it: `/`-separated, and on Windows
/// `/C:/dir` with no `\\?\` prefix.
fn client_path(p: &Path) -> String {
    #[cfg(windows)]
    {
        let s = p.to_string_lossy().replace('\\', "/");
        let s = s.strip_prefix("//?/").unwrap_or(&s).to_string();
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            return format!("/{s}");
        }
        s
    }
    #[cfg(not(windows))]
    {
        p.to_string_lossy().into_owned()
    }
}

/// `p` made absolute against the working directory (the account's home) and
/// with `.`/`..` removed. Symlinks are resolved where the path exists;
/// a path that does not exist yet (a file about to be uploaded) is resolved
/// lexically, as OpenSSH's server does for its last component.
fn resolve(p: &Path) -> std::io::Result<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(p) {
        return Ok(c);
    }
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()?.join(p)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    Ok(out)
}

/// The account's home: where `~` points. The daemon starts this process there.
fn home() -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    let var = std::env::var_os("USERPROFILE");
    #[cfg(not(windows))]
    let var = std::env::var_os("HOME");
    match var {
        Some(h) if !h.is_empty() => Ok(PathBuf::from(h)),
        _ => std::env::current_dir(),
    }
}

/// `~` and `~/x` against the home directory; `~user` is not this account's to
/// answer and is refused.
fn expand(path: &str) -> Result<PathBuf, StatusCode> {
    if path == "~" {
        return home().map_err(status_of);
    }
    if let Some(rest) = path.strip_prefix("~/") {
        return Ok(home().map_err(status_of)?.join(rest));
    }
    if path.starts_with('~') {
        return Err(StatusCode::NoSuchFile);
    }
    path_of(path)
}

fn name_of(id: u32, path: String) -> Name {
    Name {
        id,
        files: vec![File::dummy(path)],
    }
}

/// The one string an extended request carries (`string path`).
fn first_string(data: &[u8]) -> Option<String> {
    let len = u32::from_be_bytes(data.get(..4)?.try_into().ok()?) as usize;
    let bytes = data.get(4..4 + len)?;
    String::from_utf8(bytes.to_vec()).ok()
}

#[cfg(windows)]
fn drive_list() -> Vec<File> {
    (b'A'..=b'Z')
        .map(|d| format!("{}:", d as char))
        .filter(|d| Path::new(&format!("{d}\\")).exists())
        .map(|d| File::new(d, root_attrs()))
        .collect()
}

async fn set_attrs(path: &Path, attrs: &FileAttributes) -> Result<(), StatusCode> {
    if let Some(size) = attrs.size {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(status_of)?;
        f.set_len(size).map_err(status_of)?;
    }
    if let Some(mode) = attrs.permissions {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode & 0o7777))
                .map_err(status_of)?;
        }
        #[cfg(windows)]
        {
            let mut perms = std::fs::metadata(path).map_err(status_of)?.permissions();
            perms.set_readonly(mode & 0o200 == 0);
            std::fs::set_permissions(path, perms).map_err(status_of)?;
        }
    }
    if attrs.atime.is_some() || attrs.mtime.is_some() {
        let meta = std::fs::metadata(path).map_err(status_of)?;
        // A directory's times on Windows need a handle this cannot open; the
        // file's own (what `scp -p` sets) is what matters.
        if !(cfg!(windows) && meta.is_dir()) {
            let at = |s: u32| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s.into());
            let mut times = std::fs::FileTimes::new();
            if let Some(a) = attrs.atime {
                times = times.set_accessed(at(a));
            }
            if let Some(m) = attrs.mtime {
                times = times.set_modified(at(m));
            }
            let f = std::fs::OpenOptions::new()
                .write(cfg!(windows))
                .read(!cfg!(windows))
                .open(path)
                .map_err(status_of)?;
            f.set_times(times).map_err(status_of)?;
        }
    }
    // uid/gid: this process is the session's own account and cannot give a
    // file away; OpenSSH's server refuses the same request for the same reason.
    Ok(())
}

impl russh_sftp::server::Handler for Fs {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        let mut v = Version::new();
        v.extensions
            .insert(EXPAND_PATH.to_string(), "1".to_string());
        Ok(v)
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let path = path_of(&filename)?;
        #[allow(unused_mut)]
        let mut opts: std::fs::OpenOptions = pflags.into();
        #[cfg(unix)]
        if let Some(mode) = attrs.permissions {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode & 0o7777);
        }
        #[cfg(not(unix))]
        let _ = &attrs;
        let file = tokio::fs::OpenOptions::from(opts)
            .open(&path)
            .await
            .map_err(status_of)?;
        let handle = self.insert(Entry::File(file))?;
        Ok(Handle { id, handle })
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        match self.handles.remove(&handle) {
            Some(Entry::File(mut f)) => {
                f.flush().await.map_err(status_of)?;
                Ok(ok(id))
            }
            Some(Entry::Dir(_)) => Ok(ok(id)),
            None => Err(StatusCode::Failure),
        }
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let f = self.file(&handle)?;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(status_of)?;
        let mut data = vec![0u8; len.min(MAX_READ) as usize];
        let mut filled = 0;
        while filled < data.len() {
            let n = f.read(&mut data[filled..]).await.map_err(status_of)?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 && !data.is_empty() {
            return Err(StatusCode::Eof);
        }
        data.truncate(filled);
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let f = self.file(&handle)?;
        f.seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(status_of)?;
        f.write_all(&data).await.map_err(status_of)?;
        Ok(ok(id))
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let attrs = match target(&path) {
            #[cfg(windows)]
            Target::Drives => root_attrs(),
            #[cfg(not(windows))]
            Target::Drives => return Err(StatusCode::NoSuchFile),
            Target::Path(p) => attrs_of(&tokio::fs::symlink_metadata(&p).await.map_err(status_of)?),
        };
        Ok(Attrs { id, attrs })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let attrs = match target(&path) {
            #[cfg(windows)]
            Target::Drives => root_attrs(),
            #[cfg(not(windows))]
            Target::Drives => return Err(StatusCode::NoSuchFile),
            Target::Path(p) => attrs_of(&tokio::fs::metadata(&p).await.map_err(status_of)?),
        };
        Ok(Attrs { id, attrs })
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let f = self.file(&handle)?;
        let meta = f.metadata().await.map_err(status_of)?;
        Ok(Attrs {
            id,
            attrs: attrs_of(&meta),
        })
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        set_attrs(&path_of(&path)?, &attrs).await?;
        Ok(ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let f = self.file(&handle)?;
        if let Some(size) = attrs.size {
            f.set_len(size).await.map_err(status_of)?;
        }
        f.flush().await.map_err(status_of)?;
        let std_file = f.try_clone().await.map_err(status_of)?.into_std().await;
        let rest = FileAttributes {
            size: None,
            ..attrs
        };
        tokio::task::spawn_blocking(move || -> Result<(), StatusCode> {
            if let Some(mode) = rest.permissions {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std_file
                        .set_permissions(std::fs::Permissions::from_mode(mode & 0o7777))
                        .map_err(status_of)?;
                }
                #[cfg(windows)]
                {
                    let mut perms = std_file.metadata().map_err(status_of)?.permissions();
                    perms.set_readonly(mode & 0o200 == 0);
                    std_file.set_permissions(perms).map_err(status_of)?;
                }
            }
            if rest.atime.is_some() || rest.mtime.is_some() {
                let at = |s: u32| std::time::UNIX_EPOCH + std::time::Duration::from_secs(s.into());
                let mut times = std::fs::FileTimes::new();
                if let Some(a) = rest.atime {
                    times = times.set_accessed(at(a));
                }
                if let Some(m) = rest.mtime {
                    times = times.set_modified(at(m));
                }
                std_file.set_times(times).map_err(status_of)?;
            }
            Ok(())
        })
        .await
        .map_err(|_| StatusCode::Failure)??;
        Ok(ok(id))
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let files = match target(&path) {
            #[cfg(windows)]
            Target::Drives => drive_list(),
            #[cfg(not(windows))]
            Target::Drives => return Err(StatusCode::NoSuchFile),
            Target::Path(dir) => {
                let mut rd = tokio::fs::read_dir(&dir).await.map_err(status_of)?;
                let mut files = Vec::new();
                for dot in [".", ".."] {
                    if let Ok(meta) = tokio::fs::metadata(dir.join(dot)).await {
                        files.push(File::new(dot, attrs_of(&meta)));
                    }
                }
                while let Some(entry) = rd.next_entry().await.map_err(status_of)? {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    match tokio::fs::symlink_metadata(entry.path()).await {
                        Ok(meta) => files.push(File::new(name, attrs_of(&meta))),
                        // Gone between the listing and the stat, or not ours
                        // to stat: listed with no attributes, as OpenSSH does.
                        Err(_) => files.push(File::new(name, FileAttributes::empty())),
                    }
                }
                files
            }
        };
        // Served back to front, so reverse once here to keep the OS's order.
        let mut files = files;
        files.reverse();
        let handle = self.insert(Entry::Dir(files))?;
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        match self.handles.get_mut(&handle) {
            Some(Entry::Dir(rest)) => {
                if rest.is_empty() {
                    return Err(StatusCode::Eof);
                }
                let take = rest.len().min(READDIR_BATCH);
                let at = rest.len() - take;
                let mut files = rest.split_off(at);
                files.reverse();
                Ok(Name { id, files })
            }
            _ => Err(StatusCode::Failure),
        }
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_file(path_of(&filename)?)
            .await
            .map_err(status_of)?;
        Ok(ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = path_of(&path)?;
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(attrs.permissions.map_or(0o777, |m| m & 0o7777));
        }
        #[cfg(not(unix))]
        let _ = &attrs;
        builder.create(&path).map_err(status_of)?;
        Ok(ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        tokio::fs::remove_dir(path_of(&path)?)
            .await
            .map_err(status_of)?;
        Ok(ok(id))
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let resolved = match target(&path) {
            Target::Drives => "/".to_string(),
            Target::Path(p) => client_path(&resolve(&p).map_err(status_of)?),
        };
        Ok(name_of(id, resolved))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        let (from, to) = (path_of(&oldpath)?, path_of(&newpath)?);
        // SFTP v3's rename never replaces (OpenSSH's own server refuses it
        // too); only the `posix-rename` extension may, and it is not offered.
        if tokio::fs::symlink_metadata(&to).await.is_ok() {
            return Err(StatusCode::Failure);
        }
        tokio::fs::rename(&from, &to).await.map_err(status_of)?;
        Ok(ok(id))
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = tokio::fs::read_link(path_of(&path)?)
            .await
            .map_err(status_of)?;
        Ok(name_of(id, client_path(&target)))
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        // OpenSSH's client sends the TARGET first and the new link second (the
        // reverse of the draft, which every server since has followed), so the
        // crate's `linkpath` is the target here.
        #[cfg(unix)]
        {
            tokio::fs::symlink(path_of(&linkpath)?, path_of(&targetpath)?)
                .await
                .map_err(status_of)?;
            Ok(ok(id))
        }
        #[cfg(not(unix))]
        {
            let _ = (id, linkpath, targetpath);
            Err(StatusCode::OpUnsupported)
        }
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<Packet, Self::Error> {
        if request != EXPAND_PATH {
            return Err(StatusCode::OpUnsupported);
        }
        let path = first_string(&data).ok_or(StatusCode::BadMessage)?;
        let expanded = expand(&path)?;
        let resolved = resolve(&expanded).map_err(status_of)?;
        Ok(Packet::Name(name_of(id, client_path(&resolved))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::client::SftpSession;

    /// A server on one end of a pipe, the crate's client on the other.
    async fn session() -> SftpSession {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (r, w) = tokio::io::split(server);
        tokio::spawn(serve(r, w));
        SftpSession::new(client).await.expect("sftp handshake")
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "mh-sftp-builtin-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn p(path: &Path) -> String {
        client_path(path)
    }

    #[tokio::test]
    async fn a_file_goes_up_and_comes_back_byte_for_byte() {
        let dir = tmp("roundtrip");
        let sftp = session().await;
        // Larger than one READ and one WRITE, and not a multiple of either.
        let body: Vec<u8> = (0..(3 * MAX_READ as usize + 12_345))
            .map(|i| (i * 31 % 251) as u8)
            .collect();
        let path = p(&dir.join("payload.bin"));
        let mut f = sftp.create(path.clone()).await.unwrap();
        f.write_all(&body).await.unwrap();
        f.shutdown().await.unwrap();
        drop(f);
        assert_eq!(std::fs::read(dir.join("payload.bin")).unwrap(), body);

        let mut back = Vec::new();
        let mut f = sftp.open(path.clone()).await.unwrap();
        f.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, body);
        assert_eq!(
            sftp.metadata(path).await.unwrap().size,
            Some(body.len() as u64)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn listing_mkdir_rename_and_remove_do_what_they_say() {
        let dir = tmp("ops");
        let sftp = session().await;
        std::fs::write(dir.join("a.txt"), b"a").unwrap();
        sftp.create_dir(p(&dir.join("sub"))).await.unwrap();
        assert!(dir.join("sub").is_dir());

        let names: Vec<String> = sftp
            .read_dir(p(&dir))
            .await
            .unwrap()
            .map(|e| e.file_name())
            .collect();
        assert!(names.contains(&"a.txt".to_string()), "{names:?}");
        assert!(names.contains(&"sub".to_string()), "{names:?}");

        sftp.rename(p(&dir.join("a.txt")), p(&dir.join("b.txt")))
            .await
            .unwrap();
        assert!(dir.join("b.txt").is_file() && !dir.join("a.txt").exists());
        // v3 rename never replaces an existing file.
        std::fs::write(dir.join("c.txt"), b"c").unwrap();
        assert!(
            sftp.rename(p(&dir.join("b.txt")), p(&dir.join("c.txt")))
                .await
                .is_err()
        );
        assert_eq!(std::fs::read(dir.join("c.txt")).unwrap(), b"c");

        sftp.remove_file(p(&dir.join("b.txt"))).await.unwrap();
        sftp.remove_dir(p(&dir.join("sub"))).await.unwrap();
        assert!(!dir.join("b.txt").exists() && !dir.join("sub").exists());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn a_missing_file_is_no_such_file_not_a_hang() {
        let dir = tmp("missing");
        let sftp = session().await;
        let opened = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            sftp.open(p(&dir.join("nope"))),
        )
        .await
        .expect("the server answers a missing file instead of hanging");
        assert!(opened.is_err(), "opening a missing file must fail");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn realpath_resolves_a_path_that_does_not_exist_yet_lexically() {
        let dir = tmp("realpath");
        let canon = std::fs::canonicalize(&dir).unwrap();
        let p = resolve(&dir.join("x").join("..").join("new.bin")).unwrap();
        assert_eq!(p, canon.join("new.bin"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn tilde_is_this_accounts_home_and_no_one_elses() {
        let h = home().unwrap();
        assert_eq!(expand("~").unwrap(), h);
        assert_eq!(expand("~/a/b").unwrap(), h.join("a/b"));
        assert!(expand("~root/x").is_err());
    }

    #[test]
    fn the_subcommand_is_the_whole_argv_or_nothing() {
        // The test binary's own argv is not `sftp-server`.
        assert!(!requested());
    }

    #[test]
    fn an_extended_requests_one_string_is_read_by_its_length() {
        let mut data = 5u32.to_be_bytes().to_vec();
        data.extend_from_slice(b"~/abc-trailing");
        assert_eq!(first_string(&data).as_deref(), Some("~/abc"));
        assert_eq!(first_string(&[0, 0, 0, 9, b'x']), None);
    }

    #[cfg(windows)]
    #[test]
    fn windows_paths_take_the_openssh_for_windows_form() {
        assert!(matches!(target("/"), Target::Drives));
        assert!(matches!(target("/C:/Users"), Target::Path(p) if p == Path::new(r"C:\Users")));
        assert!(matches!(target("C:/Users"), Target::Path(p) if p == Path::new(r"C:\Users")));
        assert!(matches!(target("/C:"), Target::Path(p) if p == Path::new(r"C:\")));
        assert_eq!(client_path(Path::new(r"\\?\C:\Users\x")), "/C:/Users/x");
    }
}
