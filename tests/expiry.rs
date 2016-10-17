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

static EE_CERT: &'static [u8] = include_bytes!("expiry/ee.der");
static EE_LONG_CERT: &'static [u8] = include_bytes!("expiry/eelong.der");

pub fn expect_expiry(when: i64, ee: &'static [u8], expect_err: Option<Error>) {
    let ca = include_bytes!("expiry/ca.der");

    let ee_input = Input::from(ee);
    let inter_vec = vec![];
    let anchors = vec![
        trust_anchor_util::cert_der_as_trust_anchor(
            Input::from(ca)
        ).unwrap()
    ];

    let rough_time = time::Timespec::new(when, 0);

    let cert = EndEntityCert::from(ee_input).unwrap();
    let rc = cert.verify_is_valid_tls_server_cert(ALL_SIGALGS,
                                                  &anchors,
                                                  &inter_vec,
                                                  rough_time);

    assert_eq!(expect_err, rc.err());
}

#[test]
pub fn valid() {
    expect_expiry(1479496432, EE_CERT, None);
}

#[test]
pub fn expired_ee_before() {
    expect_expiry(1476644886, EE_CERT, Some(Error::CertNotValidYet));
}

#[test]
pub fn expired_ee_after() {
    expect_expiry(1479496434, EE_CERT, Some(Error::CertExpired));
}

#[test]
pub fn expired_ca_after() {
    expect_expiry(1528571613, EE_LONG_CERT, Some(Error::UnknownIssuer));
}
