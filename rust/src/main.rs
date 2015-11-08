#![feature(hashmap_hasher)]
#![feature(range_inclusive)]
extern crate fnv;

use std::collections::hash_state::DefaultState;
use std::collections::HashMap;
use std::iter;
use fnv::FnvHasher;
use std::mem;
use std::thread;
use std::sync::Arc;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::process::exit;

type FnvHashMap<K, V> = HashMap<K, V, DefaultState<FnvHasher>>;

const KEYSIZE: usize = 7;
const SBOXSIZE: usize = 5;
const BLOCKSIZE: usize = 5;
const SBOX_ARRAY: [u8; 32] = [22, 0, 19, 9, 15, 3, 21, 18, 4, 26, 28, 13, 27, 5, 25, 31, 29, 12,
                              24, 6, 23, 8, 2, 11, 16, 30, 14, 10, 20, 7, 17, 1];
const RSBOX_ARRAY: [u8; 32] = [1, 31, 22, 5, 8, 13, 19, 29, 21, 3, 27, 23, 17, 11, 26, 4, 24, 30,
                               7, 2, 28, 6, 0, 20, 18, 14, 9, 12, 10, 16, 25, 15];

type Key = [u8];

fn add_key(state: u64, key: u8) -> u64 {
    [key, key ^ 0xFF]
        .iter()
        .cycle()
        .take(BLOCKSIZE)
        .fold(0u64, |acc, &item| (acc << 8) | (item as u64)) ^ state
}

fn ror(v: u64) -> u64 {
    let tmp = (v & 0xFF) << 8 * (BLOCKSIZE - 1);
    (v >> 8) | tmp
}

fn rol(v: u64) -> u64 {
    let tmp = (v & (0xFF << (8 * (BLOCKSIZE - 1)))) >> (8 * (BLOCKSIZE - 1));
    (v << 8) | tmp
}

fn sbox(state: u64) -> u64 {
    let mut result = 0u64;
    let loops = BLOCKSIZE * 8 / SBOXSIZE;
    for i in 0..loops {
        result = result << SBOXSIZE;
        result = result |
                 SBOX_ARRAY[((state >> SBOXSIZE * (loops - i - 1)) & 0x1F) as usize] as u64;
    }
    result
}

fn rsbox(state: u64) -> u64 {
    let mut result = 0u64;
    let loops = BLOCKSIZE * 8 / SBOXSIZE;
    for i in 0..loops {
        result = result << SBOXSIZE;
        result = result |
                 RSBOX_ARRAY[((state >> SBOXSIZE * (loops - i - 1)) & 0x1F) as usize] as u64;
    }
    result
}

fn encrypt_block(msg: u64, key: &Key, rounds: usize) -> u64 {
    let mut state = msg;
    for key_byte in key.iter().take(rounds) {
        state = add_key(state, *key_byte);
        state = sbox(state);
        state = ror(state);
    }
    if rounds == KEYSIZE - 1 {
        add_key(state, key[6])
    } else {
        state
    }
}

fn decrypt_block(msg: u64, key: &Key, rounds: usize) -> u64 {
    let mut state = msg;
    state = add_key(state, *key.last().unwrap());
    for key_byte in key.iter().rev().skip(1).take(rounds) {
        state = rol(state);
        state = rsbox(state);
        state = add_key(state, *key_byte);
    }
    state
}

fn decrypt_solver_thread(lower: u32,
                         upper: u32,
                         map: Arc<FnvHashMap<u64, u32>>,
                         plains: Arc<Vec<u64>>,
                         crypts: Arc<Vec<u64>>)
                         -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for i in iter::range_inclusive(lower, upper) {
            let key = unsafe { mem::transmute::<u32, [u8; 4]>(i) };
            let maybe_key = {
                map.get(&decrypt_block(crypts[0], &key, 4))
            };
            if let Some(lower_key) = maybe_key {
                let lower_key = unsafe { mem::transmute::<u32, [u8; 4]>(*lower_key) };
                let key = lower_key.iter()
                                   .take(3)
                                   .chain(key.iter())
                                   .map(|&x| x)
                                   .collect::<Vec<u8>>();
                if plains.iter()
                         .zip(crypts.iter())
                         .all(|(&p, &c)| encrypt_block(p, &*key, 6) == c) {
                    print!("{}: ", env::args().nth(1).unwrap());
                    println!("{:#010X}", key.iter().fold(0u64, |acc, &item| (acc<<8)|item as u64));
                    exit(0);
                }
            }
        }
    })
}

fn parse_input_file() -> Result<(Vec<u64>, Vec<u64>), String> {
    let mut plains: Vec<u64> = vec![];
    let mut crypts: Vec<u64> = vec![];
    let input_file = try!(env::args()
                              .nth(1)
                              .ok_or_else(|| "Couldn't read command line argument.".to_owned()));
    let f = try!(File::open(input_file).map_err(|_| "Couldn't read input file.".to_owned()));
    let f = BufReader::new(f);
    for line in f.lines().skip(1) {
        let tmp = try!(line.map_err(|_| "Couldn't read line.".to_owned()));
        let tmp_splitted = tmp.split(",").collect::<Vec<&str>>();
        let plain_str = try!(tmp_splitted.get(0).ok_or_else(|| "Couldn't split line."));
        let (_prefix, plain_str) = plain_str.split_at(2);
        let crypt_str = try!(tmp_splitted.get(1).ok_or_else(|| "Couldn't split line."));
        let (_prefix, crypt_str) = crypt_str.split_at(2);
        let plain = try!(u64::from_str_radix(plain_str, 16)
                             .map_err(|_| "Can't parse plaintext string to u64".to_owned()));
        let crypt = try!(u64::from_str_radix(crypt_str, 16)
                             .map_err(|_| "Can't parse crypttext string to u64".to_owned()));
        plains.push(plain);
        crypts.push(crypt);
    }
    Ok((plains, crypts))
}

fn main() {
    let (plains, crypts) = match parse_input_file() {
        Ok(r) => r,
        Err(e) => {
            println!("{}", e);
            exit(1);
        }
    };
    let shared_plains = Arc::new(plains);
    let shared_crypts = Arc::new(crypts);
    let mut hashmap: FnvHashMap<u64, u32> = Default::default();
    hashmap.reserve(1 << 24);
    for i in 0..1 << 24 {
        hashmap.insert(encrypt_block(shared_plains[0],
                                     &unsafe { mem::transmute::<u32, [u8; 4]>(i) },
                                     3),
                       i);
    }
    let shared_map = Arc::new(hashmap);
    let join_handles: Vec<_> = iter::range_inclusive(0, 7)
                                   .map(|i| {
                                       decrypt_solver_thread(i * (0xFFFFFFFF / 8),
                                                             (i + 1) * (0xFFFFFFFF / 8),
                                                             shared_map.clone(),
                                                             shared_plains.clone(),
                                                             shared_crypts.clone())
                                   })
                                   .collect();
    for j in join_handles {
        let _ = j.join();
    }
}
