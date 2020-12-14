use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Write;
use std::fs::OpenOptions;
use std::fs;

use curve25519_dalek::ristretto::{RistrettoPoint};
use rug::Integer;
use rayon::prelude::*;
use chrono::{DateTime, Utc};
use tempfile::NamedTempFile;
use uuid::Uuid;
use std::io;

use crate::group::*;
use crate::elgamal::*;
use crate::artifact::*;

pub fn read_file_bytes(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

pub fn write_file_bytes(path: &Path, bytes: &Vec<u8>) -> io::Result<()> {
    fs::write(path, bytes)?;
    Ok(())
}

pub fn write_to_tmp(bytes: Vec<u8>) -> io::Result<NamedTempFile> {
    let tmp_file = NamedTempFile::new().unwrap();
    let path = tmp_file.path();
    fs::write(path, bytes)?;
    Ok(tmp_file)
}

pub fn to_u8_30(input: &Vec<u8>) -> [u8; 30] {
    assert_eq!(input.len(), 30);
    let mut bytes = [0u8; 30];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn to_u8_64(input: &Vec<u8>) -> [u8; 64] {
    assert_eq!(input.len(), 64);
    let mut bytes = [0u8; 64];
    bytes.copy_from_slice(&input);
    bytes
}

pub fn create_random_file(dir: &str) -> PathBuf {
    let mut buff = Uuid::encode_buffer();
    let id = Uuid::new_v4().to_simple().encode_lower(&mut buff);
    let target = Path::new(dir).join(Path::new(&id));
    let mut output = File::create(target.clone()).unwrap();
    let now: DateTime<Utc> = Utc::now();
    writeln!(output, "File created at {}", now).unwrap();
    target
}

pub fn modify_file(file: &str) {
    let mut file = OpenOptions::new()
        .append(true)
        .open(file)
        .unwrap();
    
    let now: DateTime<Utc> = Utc::now();

    writeln!(file, "New line at {}", now).unwrap();
}


pub fn random_ristretto_ballots<G: Group<RistrettoPoint>>(n: usize, group: &G) -> Ballots<RistrettoPoint> {

    let cs = (0..n).into_par_iter().map(|_| {
            Ciphertext{
                a: group.rnd(),
                b: group.rnd()
            }
    }).collect();

    Ballots {
        ciphertexts: cs
    }
}

pub fn random_rug_ballots<G: Group<Integer>>(n: usize, group: &G) -> Ballots<Integer> {
    
    let cs = (0..n).into_par_iter().map(|_| {
            Ciphertext{
                a: group.encode(group.rnd_exp()),
                b: group.encode(group.rnd_exp())
            }
        
    }).collect();

    Ballots {
        ciphertexts: cs
    }
}