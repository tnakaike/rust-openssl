#![allow(clippy::uninlined_format_args)]

//! A program that generates ca certs, certs verified by the ca, and public
//! and private keys.

use bitflags::parser::from_str;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509Ref, X509Req, X509VerifyResult, X509};
use std::fs;
use chrono::{Utc, TimeDelta};
use std::env;

static CA_KEY_FILE: &str = "./cert/ca-key.pem";
static ROOT_CA_FILE: &str = "./cert/root-ca.pem";
static SERVER_CSR_FILE: &str = "./cert/server.csr";
static SERVER_CERT_FILE: &str = "./cert/server-cert.pem";

/// Make a CA certificate and private key
fn mk_ca_cert() -> Result<(X509, PKey<Private>), ErrorStack> {
    println!("Loading CA from {} and {}", CA_KEY_FILE, ROOT_CA_FILE);

    let key_pair = fs::read_to_string(CA_KEY_FILE).unwrap().into_bytes();
    let key_pair = Rsa::private_key_from_pem(&key_pair)?;
    let key_pair = PKey::from_rsa(key_pair)?;

    let cert = fs::read_to_string(ROOT_CA_FILE).unwrap().into_bytes();
    let cert = X509::from_pem(&cert).unwrap();

    Ok((cert, key_pair))
}

/// Make a X509 request with the given private key
fn mk_request() -> Result<X509Req, ErrorStack> {
    println!("Loading CSR from {}", SERVER_CSR_FILE);

    let req = fs::read_to_string(SERVER_CSR_FILE).unwrap().into_bytes();
    let req = X509Req::from_pem(&req).unwrap();

    Ok(req)
}

/// Make a certificate and private key signed by the given CA cert and private key
fn mk_ca_signed_cert(
    ca_cert: &X509Ref,
    ca_key_pair: &PKeyRef<Private>,
    cert_life_time_mins: i32,
) -> Result<X509, ErrorStack> {
    // let key_pair = fs::read_to_string(SERVER_KEY_FILE).unwrap().into_bytes();
    // let key_pair = Rsa::private_key_from_pem(&key_pair)?;
    // let key_pair = PKey::from_rsa(key_pair)?;

    let req = mk_request()?;
    let pubkey = req.public_key()?;

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&pubkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;

    let now = Utc::now();
    println!("now: {}", now.format("%Y%m%d%H%M%SZ").to_string());
    let td = TimeDelta::minutes(cert_life_time_mins as i64);
    let endtime = now.checked_add_signed(td).unwrap();
    println!("enddate: {}", endtime.format("%Y%m%d%H%M%SZ").to_string());

    // let not_after = Asn1Time::days_from_now(365)?;
    let not_after = Asn1Time::from_str(&endtime.format("%Y%m%d%H%M%SZ").to_string())?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    let subject_alt_name = SubjectAlternativeName::new()
        .dns("localhost")
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_alt_name)?;

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

fn real_main(cert_life_time_mins: i32) -> Result<(), ErrorStack> {
    let (ca_cert, ca_key_pair) = mk_ca_cert()?;
    let cert = mk_ca_signed_cert(&ca_cert, &ca_key_pair, cert_life_time_mins)?;

    // Verify that this cert was issued by this ca
    match ca_cert.issued(&cert) {
        X509VerifyResult::OK => println!("Certificate verified!"),
        ver_err => println!("Failed to verify certificate: {}", ver_err),
    };

    fs::write(SERVER_CERT_FILE, cert.to_pem()?);

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    println!("{:?}", args);
    match real_main(args[1].parse().unwrap()) {
        Ok(()) => println!("Finished."),
        Err(e) => println!("Error: {}", e),
    };
}
