use SSL::Digest;
use Test;

plan 5;

my $test-buffer = Buf.new: (^256).roll: 100.pick;

sub openssl($dgst, $buf = $test-buffer) {
    my $buffer-as-string = [~] map { sprintf("%02x", $_) }, $buf.list;
    qqx{
	perl -e 'print pack "H*", "$buffer-as-string"' |
	openssl dgst -$dgst -binary|
	perl -e 'print unpack "H*", join "", <>;'
    }
}

is md4($test-buffer).unpack('H*'), openssl('md4'), 'MD4';
is md5($test-buffer).unpack('H*'), openssl('md5'), 'MD5';
is sha1($test-buffer).unpack('H*'), openssl('sha1'), 'SHA-1';
is sha256($test-buffer).unpack('H*'), openssl('sha256'), 'SHA-256';
is rmd160($test-buffer).unpack('H*'), openssl('rmd160'), 'RIPEMD-160';

# vim: ft=perl6
