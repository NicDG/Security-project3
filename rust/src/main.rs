const KEYSIZE: usize = 7;
const SBOXSIZE: usize = 5;
const BLOCKSIZE: usize = 5;
const SBOX_ARRAY: [u8; 32] = [22, 0, 19, 9, 15, 3, 21, 18, 4, 26, 28, 13, 27, 5, 25, 31, 29, 12, 24,
                        6, 23, 8, 2, 11, 16, 30, 14, 10, 20, 7, 17, 1];
const RSBOX_ARRAY: [u8; 32] = [1, 31, 22, 5, 8, 13, 19, 29, 21, 3, 27, 23, 17, 11, 26, 4, 24, 30, 7,
                        2, 28, 6, 0, 20, 18, 14, 9, 12, 10, 16, 25, 15];

type Key = [u8; KEYSIZE as usize];

fn add_key(state: u64, key: u8) -> u64 {
    [key, key^0xFF].iter()
                   .cycle()
                   .take(BLOCKSIZE)
                   .fold(0u64, |acc, &item| (acc<<8)|(item as u64)) ^ state
}

fn ror(v: u64) -> u64 {
    let tmp = (v & 0xFF) << 8*(BLOCKSIZE-1);
    (v >> 8) | tmp
}

fn rol(v: u64) -> u64 {
    let tmp = (v & (0xFF<<(8*(BLOCKSIZE-1))))>>(8*(BLOCKSIZE-1));
    (v << 8) | tmp
}

fn sbox(state: u64) -> u64 {
    let mut result = 0u64;
    let loops = BLOCKSIZE*8/SBOXSIZE;
    for i in 0..loops {
        result = result << SBOXSIZE;
        result = result | SBOX_ARRAY[((state>>SBOXSIZE*(loops-i-1))&0x1F) as usize] as u64;
    }
    result
}

fn rsbox(state: u64) -> u64 {
    let mut result = 0u64;
    let loops = BLOCKSIZE*8/SBOXSIZE;
    for i in 0..loops {
        result = result << SBOXSIZE;
        result = result | RSBOX_ARRAY[((state>>SBOXSIZE*(loops-i-1))&0x1F) as usize] as u64;
    }
    result
}

fn encrypt_block(msg: u64, key: Key, rounds: usize) -> u64 {
    let mut state = msg;
    for key_byte in key.iter().take(rounds) {
        state = add_key(state, *key_byte);
        state = sbox(state);
        state = ror(state);
    }
    if(rounds == 6) {
        add_key(state, key[6])
    } else {
        state
    }
}

fn decrypt_block(msg: u64, key: Key, rounds: usize) -> u64 {
    let mut state = msg;
    state = add_key(state, key[6]);
    for key_byte in key.iter().rev().skip(1).take(rounds) {
        state = rol(state);
        state = rsbox(state);
        state = add_key(state, *key_byte);
    }
    state
}

fn main() {
    let key = [0xC0, 0xFF, 0xEE, 0x15, 0xFF, 0xFF, 0xEE];
    let enc = encrypt_block(0x00DEADBEEF, key, 3);
    println!("{:X}", enc);
    println!("{:X}", decrypt_block(0xA85A692205, key, 3));
}
