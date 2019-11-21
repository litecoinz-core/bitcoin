### Verify Binaries

#### Preparation:

Make sure you obtain the proper release signing key and verify the fingerprint with several independent sources.

```sh
$ gpg --fingerprint "The LitecoinZ Team"
pub   rsa4096 2017-11-30 [SC]
      EC97 B4DE A29A 6A53 A385  7133 ED8E 5658 4D90 BB3F
uid           [ultimate] The LitecoinZ Team (LitecoinZ: the true Litecoin 2.0) <team@litecoinz.info>
sub   rsa4096 2017-11-30 [E]
```

#### Usage:

This script attempts to download the signature file `SHA256SUMS.asc` from https://litecoinz.org.

It first checks if the signature passes, and then downloads the files specified in the file, and checks if the hashes of these files match those that are specified in the signature file.

The script returns 0 if everything passes the checks. It returns 1 if either the signature check or the hash check doesn't pass. If an error occurs the return value is 2.


```sh
./verify.sh litecoinz-core-0.11.2
./verify.sh litecoinz-core-0.12.0
./verify.sh litecoinz-core-0.13.0-rc3
```

If you only want to download the binaries of certain platform, add the corresponding suffix, e.g.:

```sh
./verify.sh litecoinz-core-0.11.2-osx
./verify.sh 0.12.0-linux
./verify.sh litecoinz-core-0.13.0-rc3-win64
```

If you do not want to keep the downloaded binaries, specify anything as the second parameter.

```sh
./verify.sh litecoinz-core-0.13.0 delete
```
