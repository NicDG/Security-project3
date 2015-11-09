# Building
This program requires a nightly rust compiler as we override the
default hash function (which is not supported in the stable
compiler). With a nightly `cargo` and `rust`, building
is done with:

```bash
cargo build --release
```

# Running
The program takes a CSV input file as an argument and prints the key for the file before exiting:

```bash
~/Security-project3/rust $ time ./target/release/bad-block-cipher teamB.csv
/home/simon/dl/teamB.csv: 0x67957F79E22784

real    0m17.559s
user    1m49.083s
sys     0m0.253s
~/Security-project3/rust $
```
