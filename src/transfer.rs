//! Client-to-Client protocol to organize file transfers
//!
//! This gives you the actual capability to transfer files, that feature that Magic Wormhole got known and loved for.
//!
//! It is bound to an [`APPID`](APPID). Only applications using that APPID (and thus this protocol) can interoperate with
//! the original Python implementation (and other compliant implementations).
//!
//! At its core, "peer messages" are exchanged over an established wormhole connection with the other side.
//! They are used to set up a [transit] portal and to exchange a file offer/accept. Then, the file is transmitted over the transit relay.

use futures::{AsyncRead, AsyncWrite, AsyncSeek};
use serde_derive::{Deserialize, Serialize};
#[cfg(test)]
use serde_json::json;
use std::sync::Arc;

use super::{core::WormholeError, transit,  AppID, Wormhole};
use futures::Future;
use log::*;
use std::{borrow::Cow, path::{Path, PathBuf}};
use std::pin::Pin;
use transit::{Transit, TransitConnectError, TransitConnector, TransitError, Abilities as TransitAbilities};
use std::{collections::{HashMap, BTreeMap}};

mod v1;
mod v2;

const APPID_RAW: &str = "lothar.com/wormhole/text-or-file-xfer";

/// The App ID associated with this protocol.
pub const APPID: AppID = AppID(Cow::Borrowed(APPID_RAW));

/// An [`crate::AppConfig`] with sane defaults for this protocol.
///
/// You **must not** change `id` and `rendezvous_url` to be interoperable.
/// The `app_version` can be adjusted if you want to disable some features.
pub const APP_CONFIG: crate::AppConfig<AppVersion> = crate::AppConfig::<AppVersion> {
    id: AppID(Cow::Borrowed(APPID_RAW)),
    rendezvous_url: Cow::Borrowed(crate::rendezvous::DEFAULT_RENDEZVOUS_SERVER),
    app_version: AppVersion::new(),
};

// TODO be more extensible on the JSON enum types (i.e. recognize unknown variants)

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    #[error("Transfer was not acknowledged by peer")]
    AckError,
    #[error("Receive checksum error")]
    Checksum,
    #[error("The file contained a different amount of bytes than advertized! Sent {} bytes, but should have been {}", sent_size, file_size)]
    FileSize { sent_size: u64, file_size: u64 },
    #[error("The file(s) to send got modified during the transfer, and thus corrupted")]
    FilesystemSkew,
    // TODO be more specific
    #[error("Unsupported offer type")]
    UnsupportedOffer,
    #[error("Something went wrong on the other side: {}", _0)]
    PeerError(String),

    /// Some deserialization went wrong, we probably got some garbage
    #[error("Corrupt JSON message received")]
    ProtocolJson(
        #[from]
        #[source]
        serde_json::Error,
    ),
    #[error("Corrupt Msgpack message received")]
    ProtocolMsgpack(
        #[from]
        #[source]
        rmp_serde::decode::Error,
    ),
    /// A generic string message for "something went wrong", i.e.
    /// the server sent some bullshit message order
    #[error("Protocol error: {}", _0)]
    Protocol(Box<str>),
    #[error(
        "Unexpected message (protocol error): Expected '{}', but got: {:?}",
        _0,
        _1
    )]
    ProtocolUnexpectedMessage(Box<str>, Box<dyn std::fmt::Debug + Send + Sync>),
    #[error("Wormhole connection error")]
    Wormhole(
        #[from]
        #[source]
        WormholeError,
    ),
    #[error("Error while establishing transit connection")]
    TransitConnect(
        #[from]
        #[source]
        TransitConnectError,
    ),
    #[error("Transit error")]
    Transit(
        #[from]
        #[source]
        TransitError,
    ),
    #[error("IO error")]
    IO(
        #[from]
        #[source]
        std::io::Error,
    ),
}

impl TransferError {
    pub(self) fn unexpected_message(
        expected: impl Into<Box<str>>,
        got: impl std::fmt::Debug + Send + Sync + 'static,
    ) -> Self {
        Self::ProtocolUnexpectedMessage(expected.into(), Box::new(got))
    }
}

/**
 * The application specific version information for this protocol.
 *
 * At the moment, this always is an empty object, but this will likely change in the future.
 */
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppVersion {
    #[serde(default)]
    abilities: Cow<'static, [Cow<'static, str>]>,
    #[serde(default)]
    transfer_v2: Option<AppVersionTransferV2Hint>,
}

// TODO check invariants during deserialization

impl AppVersion {
    const fn new() -> Self {
        Self {
            abilities: Cow::Borrowed(&[Cow::Borrowed("transfer-v1"), Cow::Borrowed("transfer-v2")]),
            transfer_v2: Some(AppVersionTransferV2Hint::new())
        }
    }

    #[allow(dead_code)]
    fn supports_v2(&self) -> bool {
        self.abilities.contains(&"transfer-v2".into())
    }
}

impl Default for AppVersion {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct AppVersionTransferV2Hint {
    supported_formats: Cow<'static, [Cow<'static, str>]>,
    transit_abilities: transit::Abilities,
}

impl AppVersionTransferV2Hint {
    const fn new() -> Self {
        Self {
            supported_formats: Cow::Borrowed(&[Cow::Borrowed("plain"), Cow::Borrowed("tar")]),
            transit_abilities: transit::Abilities::ALL_ABILITIES,
        }
    }
}

impl Default for AppVersionTransferV2Hint {
    fn default() -> Self {
        Self::new()
    }
}

pub trait AsyncReadSeek: AsyncRead + AsyncSeek {}

impl <T> AsyncReadSeek for T where T: AsyncRead + AsyncSeek {}

pub trait AsyncWriteSeek: AsyncWrite + AsyncSeek {}

impl <T> AsyncWriteSeek for T where T: AsyncWrite + AsyncSeek {}

/**
 * The type of message exchanged over the wormhole for this protocol
 */
#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum PeerMessage {
    /* V1 */
    Transit(v1::TransitV1),
    Offer(v1::OfferMessage),
    Answer(v1::AnswerMessage),
    /* V2 */
    TransitV2(v2::TransitV2),

    /** Tell the other side you got an error */
    Error(String),
    #[serde(other)]
    Unknown,
}

impl PeerMessage {
    fn offer_message_v1(msg: impl Into<String>) -> Self {
        PeerMessage::Offer(v1::OfferMessage::Message(msg.into()))
    }

    fn offer_file_v1(name: impl Into<String>, size: u64) -> Self {
        PeerMessage::Offer(v1::OfferMessage::File {
            filename: name.into(),
            filesize: size,
        })
    }

    #[allow(dead_code)]
    fn offer_directory_v1(
        name: impl Into<String>,
        mode: impl Into<String>,
        compressed_size: u64,
        numbytes: u64,
        numfiles: u64,
    ) -> Self {
        PeerMessage::Offer(v1::OfferMessage::Directory {
            dirname: name.into(),
            mode: mode.into(),
            zipsize: compressed_size,
            numbytes,
            numfiles,
        })
    }

    #[allow(dead_code)]
    fn message_ack_v1(msg: impl Into<String>) -> Self {
        PeerMessage::Answer(v1::AnswerMessage::MessageAck(msg.into()))
    }

    fn file_ack_v1(msg: impl Into<String>) -> Self {
        PeerMessage::Answer(v1::AnswerMessage::FileAck(msg.into()))
    }

    fn error_message(msg: impl Into<String>) -> Self {
        PeerMessage::Error(msg.into())
    }

    fn transit_v1(abilities: TransitAbilities, hints: transit::Hints) -> Self {
        PeerMessage::Transit(v1::TransitV1 {
            abilities_v1: abilities,
            hints_v1: hints,
        })
    }

    fn transit_v2(hints_v2: transit::Hints) -> Self {
        PeerMessage::TransitV2(v2::TransitV2 { hints_v2 })
    }

    fn check_err(&self) -> Result<Self, TransferError> {
        match self {
            Self::Error(err) => Err(TransferError::PeerError(err.clone())),
            other => Ok(other.clone()),
        }
    }

    #[allow(dead_code)]
    fn ser_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

pub struct OfferSend {
    content: HashMap<String, OfferSendEntry>,
}

impl OfferSend {
    /// Offer a single path (file or folder)
    async fn new_file_or_folder(
        offer_name: String,
        path: &Path,
    ) -> std::io::Result<Self> {
        let mut content = HashMap::new();
        content.insert(offer_name, OfferSendEntry::new(path).await?);
        Ok(Self {
            content: content
        })
    }

    /// Offer a single file with custom content
    ///
    /// You must ensure that the Reader contains exactly as many bytes
    /// as advertized in file_size.
    async fn new_file_custom(
        offer_name: String,
        size: u64,
        content: OfferContent,
    ) -> Self {
        let mut content_ = HashMap::new();
        content_.insert(offer_name, OfferSendEntry::RegularFile {
            size,
            content,
        });
        Self {
            content: content_
        }
    }

    /** Recursively list all file paths, without directory names or symlinks. */
    fn list_file_paths(&self) -> impl Iterator<Item = String> + '_ {
        self.content.iter()
            .flat_map(|(name, offer)| {
                let name = name.clone();
                offer.list_file_paths()
                    .map(move |path| format!("{name}/{path}"))
            })
    }

    fn get_file(&mut self, path: &[String]) -> Option<&mut OfferContent> {
        match path {
            [] => None,
            [start, rest @ ..] => {
                self.content.get_mut(start)
                    .and_then(|inner| inner.get_file(rest))
            }
        }
    }
}

type OfferContent = Box<dyn FnMut() -> futures::future::BoxFuture<'static, std::io::Result<Box<dyn AsyncReadSeek + Unpin + Send>>> + Send>;

pub enum OfferSendEntry {
    RegularFile {
        size: u64,
        content: OfferContent,
    },
    Directory {
        content: BTreeMap<String, Self>,
    },
    Symlink {
        target: String,
    },
}

impl OfferSendEntry {
    async fn new(path: impl AsRef<Path>) -> std::io::Result<Self> {
        // Workaround for https://github.com/rust-lang/rust/issues/78649
        #[inline(always)]
        fn new_recurse<'a>(path: impl AsRef<Path> + 'a + Send) -> futures::future::BoxFuture<'a, std::io::Result<OfferSendEntry>> {
            Box::pin(OfferSendEntry::new(path))
        }

        let path = path.as_ref();
        let metadata = async_std::fs::symlink_metadata(path).await?;
        // let mtime = metadata.modified()?
        //     .duration_since(std::time::SystemTime::UNIX_EPOCH)
        //     .unwrap_or_default()
        //     .as_secs();
        if metadata.is_file() {
            let path = path.to_owned();
            Ok(Self::RegularFile {
                size: metadata.len(),
                content: Box::new(move || {
                    let path = path.clone();
                    Box::pin(async move {
                        async_std::fs::File::open(path).await
                            .map(|file| Box::new(file) as Box<dyn AsyncReadSeek + Unpin + Send>)
                    }) as futures::future::BoxFuture<_>
                }) as _
            })
        } else if metadata.is_symlink() {
            let target = async_std::fs::read_link(path).await?;
            Ok(Self::Symlink {
                target: target.to_str().expect("TODO error handling").to_string(),
            })
        } else if metadata.is_dir() {
            use futures::TryStreamExt;

            let content: BTreeMap<String, Self> = async_std::fs::read_dir(path)
                .await?
                .and_then(|file| {
                    use futures::FutureExt;

                    let name = path.file_name().expect("TODO error handling").to_str().expect("TODO error handling").to_owned();
                    new_recurse(file.path()).map(|res| res.map(|offer| (name, offer)))
                })
                .try_collect()
                .await?;
            Ok(Self::Directory {
                content,
            })
        } else {
            unreachable!()
        }
    }

    /** Recursively list all file paths, without directory names or symlinks. */
    fn list_file_paths(&self) -> impl Iterator<Item = String> + '_ {
        // TODO I couldn't think up a less efficient way to do this ^^
        match self {
            Self::Directory { content, .. } => {
                let iter = content.iter()
                    .flat_map(|(name, offer)| {
                        let name = name.clone();
                        offer.list_file_paths()
                            .map(move |path| format!("{name}/{path}"))
                    });
                Box::new(iter) as Box<dyn Iterator<Item = String>>
            },
            _ => {
                Box::new(std::iter::empty()) as Box<dyn Iterator<Item = String>>
            }
        }
    }

    fn get_file(&mut self, path: &[String]) -> Option<&mut OfferContent> {
        match path {
            [] => match self {
                Self::RegularFile { content, ..} => Some(content),
                _ => None,
            },
            [start, rest @ ..] => match self {
                Self::Directory { content, ..} => {
                    content.get_mut(start)
                        .and_then(|inner| inner.get_file(rest))
                },
                _ => None,
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Offer {
    content: HashMap<String, OfferEntry>,
}

impl Offer {
    /** Recursively list all file paths, without directory names or symlinks. */
    pub fn list_file_paths(&self) -> impl Iterator<Item = Vec<String>> + '_ {
        // FIXME this logic is likely broken
        self.content.iter()
            .flat_map(|(name, offer)| {
                let name = name.clone();
                offer.list_file_paths()
                    .map(move |mut path| {
                        path.insert(0, name.clone());
                        path
                    })
            })
    }

    pub fn get(&self, path: &[String]) -> Option<&OfferEntry> {
        match path {
            [] => None,
            [start, rest @ ..] => {
                self.content.get(start)
                    .and_then(|inner| inner.get(rest))
            }
        }
    }

    pub fn accept_all(&self) -> Answer {
        Answer {
            files: self.list_file_paths()
                .map(|_| todo!())
                .collect(),
        }
    }
}

impl From<OfferSend> for Offer {
    fn from(from: OfferSend) -> Self {
        Self {
            content: from.content.into_iter()
                .map(|(k, v)| (k, v.into()))
                .collect()
        }
    }
}

impl From<&OfferSend> for Offer {
    fn from(from: &OfferSend) -> Self {
        Self {
            content: from.content.iter()
                .map(|(k, v)| (k.clone(), v.into()))
                .collect()
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type")]
pub enum OfferEntry {
    RegularFile {
        size: u64,
    },
    Directory {
        content: BTreeMap<String, Self>,
    },
    Symlink {
        target: String,
    },
}

impl OfferEntry {
    /** Recursively list all file paths, without directory names or symlinks. */
    fn list_file_paths(&self) -> impl Iterator<Item = Vec<String>> + '_ {
        // TODO I couldn't think up a less efficient way to do this ^^
        // FIXME this logic is likely broken
        match self {
            Self::Directory { content, .. } => {
                let iter = content.iter()
                    .flat_map(|(name, offer)| {
                        let name = name.clone();
                        offer.list_file_paths()
                            .map(move |mut path| {
                                path.insert(0, name.clone());
                                path
                            })
                    });
                Box::new(iter) as Box<dyn Iterator<Item = Vec<String>>>
            },
            _ => {
                Box::new(std::iter::empty()) as Box<dyn Iterator<Item = Vec<String>>>
            }
        }
    }

    fn get(&self, path: &[String]) -> Option<&Self> {
        match path {
            [] => Some(self),
            [start, rest @ ..] => match self {
                Self::Directory { content, ..} => {
                    content.get(start)
                        .and_then(|inner| inner.get(rest))
                },
                _ => None,
            }
        }
    }
}

impl From<OfferSendEntry> for OfferEntry {
    fn from(from: OfferSendEntry) -> Self {
        match from {
            OfferSendEntry::RegularFile { size, .. } => Self::RegularFile { size },
            OfferSendEntry::Directory { content } => Self::Directory {
                content: content.into_iter().map(|(k, v)| (k, v.into())).collect()
            },
            OfferSendEntry::Symlink { target } => Self::Symlink { target },
        }
    }
}

impl From<&OfferSendEntry> for OfferEntry {
    fn from(from: &OfferSendEntry) -> Self {
        match from {
            OfferSendEntry::RegularFile { size, .. } => Self::RegularFile { size: *size },
            OfferSendEntry::Directory { content } => Self::Directory {
                content: content.iter().map(|(k, v)| (k.clone(), v.into())).collect()
            },
            OfferSendEntry::Symlink { target } => Self::Symlink { target: target.clone() },
        }
    }
}

type AnswerContent = Box<dyn FnMut() -> futures::future::BoxFuture<'static, std::io::Result<Box<dyn AsyncWriteSeek + Unpin + Send>>> + Send>;

pub struct Answer {
    pub(self) files: BTreeMap<Vec<String>, AnswerInner>,
}

pub(self) struct AnswerInner {
    pub offset: u64,
    pub sha256: Option<[u8; 32]>,
    pub content: AnswerContent,
}

pub async fn send(
    wormhole: Wormhole,
    relay_url: url::Url,
    transit_abilities: transit::Abilities,
    offer: OfferSend,
    transit_handler: impl FnOnce(transit::TransitInfo, std::net::SocketAddr),
    progress_handler: impl FnMut(u64, u64) + 'static,
) -> Result<(), TransferError> {
    let peer_version: AppVersion = serde_json::from_value(wormhole.peer_version.clone())?;
    let relay_hints = vec![transit::RelayHint::from_urls(None, [relay_url])];
    if peer_version.supports_v2() && false {
        v2::send(wormhole, relay_hints, offer, progress_handler, peer_version).await
    } else {
        v1::send(wormhole, relay_hints, offer, progress_handler, peer_version).await
    }
}

/**
 * Wait for a file offer from the other side
 *
 * This method waits for an offer message and builds up a [`ReceiveRequest`](ReceiveRequest).
 * It will also start building a TCP connection to the other side using the transit protocol.
 *
 * Returns `None` if the task got cancelled.
 */
pub async fn request(
    wormhole: Wormhole,
    relay_url: url::Url,
    transit_abilities: transit::Abilities,
    cancel: impl Future<Output = ()>,
) -> Result<Option<ReceiveRequest>, TransferError> {
    let peer_version: AppVersion = serde_json::from_value(wormhole.peer_version.clone())?;
    let relay_hints = vec![transit::RelayHint::from_urls(None, [relay_url])];
    if peer_version.supports_v2() && false {
        v2::request(wormhole, relay_hints, peer_version).await
            .map(|req| req.map(ReceiveRequestInner::V2).map(ReceiveRequest))
    } else {
        v1::request(wormhole, relay_hints, transit_abilities, cancel).await
            .map(|req| req.map(ReceiveRequestInner::V1).map(ReceiveRequest))
    }
}

/**
 * A pending files send offer from the other side
 *
 * You *should* consume this object, either by calling [`accept`](ReceiveRequest::accept) or [`reject`](ReceiveRequest::reject).
 */
#[must_use]
pub struct ReceiveRequest(ReceiveRequestInner);

enum ReceiveRequestInner {
    V1(v1::ReceiveRequest),
    V2(v2::ReceiveRequest),
}

impl ReceiveRequest {
    /** The offer we got */
    pub fn offer(&self) -> Arc<Offer> {
        match &self.0 {
            ReceiveRequestInner::V1(req) => req.offer(),
            ReceiveRequestInner::V2(req) => req.offer(),
        }
    }

    /**
     * Accept the file offer
     *
     * This will transfer the file and save it on disk.
     */
    pub async fn accept<F, G, W>(
        self,
        transit_handler: G,
        progress_handler: F,
        answer: Answer,
        cancel: impl Future<Output = ()>,
    ) -> Result<(), TransferError>
    where
        F: FnMut(u64, u64) + 'static,
        G: FnOnce(transit::TransitInfo, std::net::SocketAddr),
        W: AsyncWrite + Unpin,
    {
        match self.0 {
            ReceiveRequestInner::V1(req) => req.accept(transit_handler, answer, progress_handler, cancel).await,
            ReceiveRequestInner::V2(req) => req.accept(transit_handler, answer, progress_handler, cancel).await,
        }
    }

    /**
     * Reject the file offer
     *
     * This will send an error message to the other side so that it knows the transfer failed.
     */
    pub async fn reject(self) -> Result<(), TransferError> {
        match self.0 {
            ReceiveRequestInner::V1(req) => req.reject().await,
            ReceiveRequestInner::V2(req) => req.reject().await,
        }
    }
}

/// Maximum duration that we are willing to wait for cleanup tasks to finish
const SHUTDOWN_TIME: std::time::Duration = std::time::Duration::from_secs(5);

/** Handle the post-{transfer, failure, cancellation} logic */
async fn handle_run_result(
    mut wormhole: Wormhole,
    result: Result<(Result<(), TransferError>, impl Future<Output = ()>), crate::util::Cancelled>,
) -> Result<(), TransferError> {
    async fn wrap_timeout(run: impl Future<Output = ()>, cancel: impl Future<Output = ()>) {
        let run = async_std::future::timeout(SHUTDOWN_TIME, run);
        futures::pin_mut!(run);
        match crate::util::cancellable(run, cancel).await {
            Ok(Ok(())) => {},
            Ok(Err(_timeout)) => log::debug!("Post-transfer timed out"),
            Err(_cancelled) => log::debug!("Post-transfer got cancelled by user"),
        };
    }

    /// Ignore an error but at least debug print it
    fn debug_err(result: Result<(), WormholeError>, operation: &str) {
        if let Err(error) = result {
            log::debug!("Failed to {} after transfer: {}", operation, error);
        }
    }

    match result {
        /* Happy case: everything went okay */
        Ok((Ok(()), cancel)) => {
            log::debug!("Transfer done, doing cleanup logic");
            wrap_timeout(
                async {
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                cancel,
            )
            .await;
            Ok(())
        },
        /* Got peer error: stop everything immediately */
        Ok((Err(error @ TransferError::PeerError(_)), cancel)) => {
            log::debug!(
                "Transfer encountered an error ({}), doing cleanup logic",
                error
            );
            wrap_timeout(
                async {
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                cancel,
            )
            .await;
            Err(error)
        },
        /* Got transit error: try receive peer error for better error message */
        Ok((Err(mut error @ TransferError::Transit(_)), cancel)) => {
            log::debug!(
                "Transfer encountered an error ({}), doing cleanup logic",
                error
            );
            wrap_timeout(async {
                /* If transit failed, ask for a proper error and potentially use that instead */
                // TODO this should be replaced with some try_receive that only polls already available messages,
                // and we should not only look for the next one but all have been received
                // and we should not interrupt a receive operation without making sure it leaves the connection
                // in a consistent state, otherwise the shutdown may cause protocol errors
                if let Ok(Ok(Ok(PeerMessage::Error(e)))) = async_std::future::timeout(SHUTDOWN_TIME / 3, wormhole.receive_json()).await {
                    error = TransferError::PeerError(e);
                } else {
                    log::debug!("Failed to retrieve more specific error message from peer. Maybe it crashed?");
                }
                debug_err(wormhole.close().await, "close Wormhole");
            }, cancel).await;
            Err(error)
        },
        /* Other error: try to notify peer */
        Ok((Err(error), cancel)) => {
            log::debug!(
                "Transfer encountered an error ({}), doing cleanup logic",
                error
            );
            wrap_timeout(
                async {
                    debug_err(
                        wormhole
                            .send_json(&PeerMessage::Error(format!("{}", error)))
                            .await,
                        "notify peer about the error",
                    );
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                cancel,
            )
            .await;
            Err(error)
        },
        /* Cancelled: try to notify peer */
        Err(cancelled) => {
            log::debug!("Transfer got cancelled, doing cleanup logic");
            /* Replace cancel with ever-pending future, as we have already been cancelled */
            wrap_timeout(
                async {
                    debug_err(
                        wormhole
                            .send_json(&PeerMessage::Error(format!("{}", cancelled)))
                            .await,
                        "notify peer about our cancellation",
                    );
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                futures::future::pending(),
            )
            .await;
            Ok(())
        },
    }
}

/** Handle the post-{transfer, failure, cancellation} logic */
async fn handle_run_result_noclose<T>(
    mut wormhole: Wormhole,
    result: Result<(Result<T, TransferError>, impl Future<Output = ()>), crate::util::Cancelled>,
) -> Result<Option<(T, Wormhole)>, TransferError> {
    async fn wrap_timeout(run: impl Future<Output = ()>, cancel: impl Future<Output = ()>) {
        let run = async_std::future::timeout(SHUTDOWN_TIME, run);
        futures::pin_mut!(run);
        match crate::util::cancellable(run, cancel).await {
            Ok(Ok(())) => {},
            Ok(Err(_timeout)) => log::debug!("Post-transfer timed out"),
            Err(_cancelled) => log::debug!("Post-transfer got cancelled by user"),
        };
    }

    /// Ignore an error but at least debug print it
    fn debug_err(result: Result<(), WormholeError>, operation: &str) {
        if let Err(error) = result {
            log::debug!("Failed to {} after transfer: {}", operation, error);
        }
    }

    match result {
        /* Happy case: everything went okay */
        Ok((Ok(val), cancel)) => {
            Ok(Some((val, wormhole)))
        },
        /* Got peer error: stop everything immediately */
        Ok((Err(error @ TransferError::PeerError(_)), cancel)) => {
            log::debug!(
                "Transfer encountered an error ({}), doing cleanup logic",
                error
            );
            wrap_timeout(
                async {
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                cancel,
            )
            .await;
            Err(error)
        },
        /* Got transit error: try receive peer error for better error message */
        Ok((Err(mut error @ TransferError::Transit(_)), cancel)) => {
            log::debug!(
                "Transfer encountered an error ({}), doing cleanup logic",
                error
            );
            wrap_timeout(async {
                /* If transit failed, ask for a proper error and potentially use that instead */
                // TODO this should be replaced with some try_receive that only polls already available messages,
                // and we should not only look for the next one but all have been received
                // and we should not interrupt a receive operation without making sure it leaves the connection
                // in a consistent state, otherwise the shutdown may cause protocol errors
                if let Ok(Ok(Ok(PeerMessage::Error(e)))) = async_std::future::timeout(SHUTDOWN_TIME / 3, wormhole.receive_json()).await {
                    error = TransferError::PeerError(e);
                } else {
                    log::debug!("Failed to retrieve more specific error message from peer. Maybe it crashed?");
                }
                debug_err(wormhole.close().await, "close Wormhole");
            }, cancel).await;
            Err(error)
        },
        /* Other error: try to notify peer */
        Ok((Err(error), cancel)) => {
            log::debug!(
                "Transfer encountered an error ({}), doing cleanup logic",
                error
            );
            wrap_timeout(
                async {
                    debug_err(
                        wormhole
                            .send_json(&PeerMessage::Error(format!("{}", error)))
                            .await,
                        "notify peer about the error",
                    );
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                cancel,
            )
            .await;
            Err(error)
        },
        /* Cancelled: try to notify peer */
        Err(cancelled) => {
            log::debug!("Transfer got cancelled, doing cleanup logic");
            /* Replace cancel with ever-pending future, as we have already been cancelled */
            wrap_timeout(
                async {
                    debug_err(
                        wormhole
                            .send_json(&PeerMessage::Error(format!("{}", cancelled)))
                            .await,
                        "notify peer about our cancellation",
                    );
                    debug_err(wormhole.close().await, "close Wormhole");
                },
                futures::future::pending(),
            )
            .await;
            Ok(None)
        },
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use transit::{Abilities, DirectHint, RelayHint};

    #[test]
    fn test_transit() {
        let abilities = Abilities::ALL_ABILITIES;
        let hints = transit::Hints::new(
            [DirectHint::new("192.168.1.8", 46295)],
            [RelayHint::new(
                None,
                [DirectHint::new("magic-wormhole-transit.debian.net", 4001)],
                [],
            )],
        );
        assert_eq!(
            serde_json::json!(crate::transfer::PeerMessage::transit_v1(abilities, hints)),
            serde_json::json!({
                "transit": {
                    "abilities-v1": [{"type":"direct-tcp-v1"},{"type":"relay-v1"}],
                    "hints-v1": [
                        {"hostname":"192.168.1.8","port":46295,"type":"direct-tcp-v1"},
                        {
                            "type": "relay-v1",
                            "hints": [
                                {"type": "direct-tcp-v1", "hostname": "magic-wormhole-transit.debian.net", "port": 4001}
                            ],
                            "name": null
                        }
                    ],
                }
            })
        );
    }

    #[test]
    fn test_message() {
        let m1 = PeerMessage::offer_message_v1("hello from rust");
        assert_eq!(
            serde_json::json!(m1).to_string(),
            "{\"offer\":{\"message\":\"hello from rust\"}}"
        );
    }

    #[test]
    fn test_offer_file() {
        let f1 = PeerMessage::offer_file_v1("somefile.txt", 34556);
        assert_eq!(
            serde_json::json!(f1).to_string(),
            "{\"offer\":{\"file\":{\"filename\":\"somefile.txt\",\"filesize\":34556}}}"
        );
    }

    #[test]
    fn test_offer_directory() {
        let d1 = PeerMessage::offer_directory_v1("somedirectory", "zipped", 45, 1234, 10);
        assert_eq!(
            serde_json::json!(d1).to_string(),
            "{\"offer\":{\"directory\":{\"dirname\":\"somedirectory\",\"mode\":\"zipped\",\"numbytes\":1234,\"numfiles\":10,\"zipsize\":45}}}"
        );
    }

    #[test]
    fn test_message_ack() {
        let m1 = PeerMessage::message_ack_v1("ok");
        assert_eq!(
            serde_json::json!(m1).to_string(),
            "{\"answer\":{\"message_ack\":\"ok\"}}"
        );
    }

    #[test]
    fn test_file_ack() {
        let f1 = PeerMessage::file_ack_v1("ok");
        assert_eq!(
            serde_json::json!(f1).to_string(),
            "{\"answer\":{\"file_ack\":\"ok\"}}"
        );
    }
}
