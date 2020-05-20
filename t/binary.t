use SSL::Digest;
use Test;

use experimental :pack;

plan 10;

my $test-buffer = Buf.new: (^256).roll: 100.pick;

sub openssl($dgst, $buf = $test-buffer) {
    my $buffer-as-string = [~] map { sprintf("%02x", $_) }, $buf.list;
    qqx{
	perl -e 'print pack "H*", "$buffer-as-string"' |
	openssl dgst -$dgst -binary 2>/dev/null |
	perl -e 'print unpack "H*", join "", <>;'
    }
}

sub test-digest(Buf $digest, Str $type, Str $desc ) {
    my $expected = openssl($type);
    if $expected {
        is $digest.unpack('H*'), $expected, $desc;
    }
    else {
        skip "unsupported digest type '$type'", 1
    }
}


test-digest md4($test-buffer), 'md4', 'MD4';
test-digest md5($test-buffer), 'md5', 'MD5';
test-digest sha0($test-buffer), 'sha', 'SHA-0';
test-digest sha1($test-buffer), 'sha1', 'SHA-1';
test-digest sha224($test-buffer), 'sha224', 'SHA-224';
test-digest sha256($test-buffer), 'sha256', 'SHA-256';
test-digest sha384($test-buffer), 'sha384', 'SHA-384';
test-digest sha512($test-buffer), 'sha512', 'SHA-512';
test-digest rmd160($test-buffer), 'rmd160', 'RIPEMD-160';
test-digest whirlpool($test-buffer), 'whirlpool', 'WHIRLPOOL';

# vim: ft=perl6
