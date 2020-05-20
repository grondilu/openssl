use SSL::Digest;
use Test;

use experimental :pack;

plan 11;

my Buf $random-bytes = Buf.new: (^128).roll: 10.pick;
sub openssl($dgst, Buf $bytes = $random-bytes) {
    my $hex = [~] map { sprintf "%02x", $_ }, $bytes.list;

    qqx{
	perl -e 'print pack q/H*/, q/$hex/' |
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

my $str = [~] map &chr, $random-bytes.list;
test-digest md4($str),'md4', 'MD4';
test-digest md5($str), 'md5', 'MD5';
test-digest sha0($str), 'sha', 'SHA-0';
test-digest sha1($str), 'sha1', 'SHA-1';
test-digest sha224($str), 'sha224', 'SHA-224';
test-digest sha256($str), 'sha256', 'SHA-256';
test-digest sha384($str), 'sha384', 'SHA-384';
test-digest sha512($str), 'sha512', 'SHA-512';
test-digest rmd160($str), 'rmd160', 'RIPEMD-160';
test-digest whirlpool($str), 'whirlpool', 'WHIRLPOOL';

# md2 no longer seems to be exposed via the openssl command line
# and 'openssl md2' silently (!) gives the same result as md5
#is md2('').unpack('H*'), '8350e5a3e24c153df2275c9f80692773', 'MD2 (empty string)';
#is md2('The quick brown fox jumps over the lazy dog').unpack('H*'), '03d85a0d629d2c442e987525319fc471', 'MD2 (quick brown fox)';

$str = "æ€!éè";
is
sha256($str).unpack('H*'),
qqx{ perl -e 'use Digest::SHA qw(sha256_hex); print sha256_hex "$str"' },
'SHA-256 with a unicode string';

# vim: ft=perl6
