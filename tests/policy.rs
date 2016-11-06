// Copyright 2016 Joseph Birr-Pixton.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

extern crate untrusted;
extern crate webpki;
extern crate ring;
extern crate time;
mod common;

use untrusted::Input;
use webpki::*;
use common::ALL_SIGALGS;

pub fn check_policy(policy: PolicyFunction, expect_err: Option<Error>) {
    let ee = include_bytes!("policy/end.der");
    let inter = include_bytes!("policy/inter.der");
    let ca = include_bytes!("policy/ca.der");

    let ee_input = Input::from(ee);
    let inters = vec![
      Input::from(inter)
    ];
    let mut trust_anchor = trust_anchor_util::cert_der_as_trust_anchor(
        Input::from(ca)).unwrap();
    trust_anchor.policy = Some(policy);
    let anchors = vec![
        trust_anchor
    ];

    let rough_time = time::Timespec::new(1479496432, 0);

    let cert = EndEntityCert::from(ee_input).unwrap();
    let rc = cert.verify_is_valid_tls_server_cert(ALL_SIGALGS,
                                                  &anchors,
                                                  &inters,
                                                  rough_time);

    assert_eq!(expect_err, rc.err());
}

fn always_allow(_whole: &[u8], _subject: &[u8], _spki: &[u8],
                _not_before: time::Timespec,
                _not_after: time::Timespec) -> Result<(), Error> {
    Ok(())
}

fn always_reject(_whole: &[u8], _subject: &[u8], _spki: &[u8],
                 _not_before: time::Timespec,
                 _not_after: time::Timespec) -> Result<(), Error> {
    Err(Error::RejectedByPolicy)
}

fn issued_before_some_date(_whole: &[u8], _subject: &[u8], _spki: &[u8],
                           not_before: time::Timespec,
                           _not_after: time::Timespec) -> Result<(), Error> {
    if not_before < time::Timespec::new(1471104423, 0) {
        Ok(())
    } else {
        Err(Error::RejectedByPolicy)
    }
}

fn is_expected_cert(whole: &[u8], _subject: &[u8], _spki: &[u8],
                    _not_before: time::Timespec,
                    _not_after: time::Timespec) -> Result<(), Error> {
    let expected_cert = include_bytes!("policy/end.der");

    if whole == &expected_cert[..] {
        Ok(())
    } else {
        Err(Error::RejectedByPolicy)
    }
}


#[test]
pub fn policy_is_called() {
    check_policy(always_reject, Some(Error::UnknownIssuer));
    check_policy(always_allow, None);
}

#[test]
pub fn policy_can_restrict_issue_date() {
    check_policy(issued_before_some_date, Some(Error::UnknownIssuer));
}

#[test]
pub fn policy_is_passed_end_entity() {
    check_policy(is_expected_cert, None);
}
