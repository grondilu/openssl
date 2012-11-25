use SSL::Digest;
use Test;

plan *;

my Buf $random-bytes .= new: (^128).roll: 10.pick;
sub openssl($dgst, Buf $bytes = $random-bytes) {
    my $hex = [~] map { sprintf "%02x", $_ }, $bytes.list;
    qqx{
	perl -e 'print pack q/H*/, q/$hex/' |
	openssl dgst -$dgst -binary |
	perl -e 'print unpack "H*", join "", <>;'
    }
}

my $str = [~] map &chr, $random-bytes.list;
is md4($str).unpack('H*'), openssl('md4'), 'MD4';
is md5($str).unpack('H*'), openssl('md5'), 'MD5';
is sha1($str).unpack('H*'), openssl('sha1'), 'SHA-1';
is sha256($str).unpack('H*'), openssl('sha256'), 'SHA-256';
is rmd160($str).unpack('H*'), openssl('rmd160'), 'RIPEMD-160';

$str = "æ€!éè";
is
sha256($str).unpack('H*'),
qqx{ perl -e 'use Digest::SHA qw(sha256_hex); print sha256_hex "$str"' },
'SHA-256 with a unicode string';

# vim: ft=perl6
