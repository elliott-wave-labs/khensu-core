// SPDX-License-Identifier: Apache-2.0
//! `KhensuContent` (PROTOCOL.md 5.1), the MLS application data.

use khensu_crypto::{Reader, write_vec};

use crate::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ContentType {
    Text = 1,
    Attachment = 2,
    Reaction = 3,
    Edit = 4,
    Delete = 5,
    Reply = 6,
    Poll = 7,
    PollVote = 8,
    ReadReceipt = 9,
    KeyReveal = 10,
    Payment = 11,
    CallInvite = 12,
    DeadmanSetup = 13,
    ChannelPost = 14,
    Profile = 15,
    GroupMeta = 16,
    DisappearingTimer = 17,
}

impl TryFrom<u16> for ContentType {
    type Error = Error;

    fn try_from(v: u16) -> Result<Self, Error> {
        use ContentType::*;
        Ok(match v {
            1 => Text,
            2 => Attachment,
            3 => Reaction,
            4 => Edit,
            5 => Delete,
            6 => Reply,
            7 => Poll,
            8 => PollVote,
            9 => ReadReceipt,
            10 => KeyReveal,
            11 => Payment,
            12 => CallInvite,
            13 => DeadmanSetup,
            14 => ChannelPost,
            15 => Profile,
            16 => GroupMeta,
            17 => DisappearingTimer,
            _ => return Err(Error::Decode),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KhensuContent {
    pub content_type: ContentType,
    pub message_id: [u8; 16],
    pub sent_at_ms: u64,
    pub expires_after_s: u32,
    pub body: Vec<u8>,
}

impl KhensuContent {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.body.len());
        out.extend_from_slice(&(self.content_type as u16).to_be_bytes());
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.sent_at_ms.to_be_bytes());
        out.extend_from_slice(&self.expires_after_s.to_be_bytes());
        write_vec(&mut out, &self.body);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(bytes);
        let c = Self {
            content_type: r.u16()?.try_into()?,
            message_id: r.array()?,
            sent_at_ms: r.u64()?,
            expires_after_s: r.u32()?,
            body: r.vec()?.to_vec(),
        };
        r.finish()?;
        Ok(c)
    }
}
