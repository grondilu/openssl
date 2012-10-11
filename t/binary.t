use SSL::Digest;
use Test;

plan 4;

my $test-buffer = Buf.new: (^256).roll: 100.pick;

sub openssl($dgst, $buf = $test-buffer) {
    qqx{
	perl -e 'print pack "H*", "{
	    [~] map { sprintf("%02x", $_) }, $buf.list
	}"' |
	openssl dgst -$dgst -binary|
	perl -e 'print unpack "H*", join "", <>;'
    }
}

is md5($test-buffer).unpack('H*'), openssl('md5'), 'MD5';
is sha1($test-buffer).unpack('H*'), openssl('sha1'), 'SHA-1';
is sha256($test-buffer).unpack('H*'), openssl('sha256'), 'SHA-256';
is rmd160($test-buffer).unpack('H*'), openssl('rmd160'), 'RIPEMD-160';

# vim: ft=perl6
