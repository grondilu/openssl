use SSL::Digest;
use Test;

plan 4;

my $test-string = 'The quick brown fox jumps over the lazy dog';
sub openssl($dgst, $str = $test-string) {
    qqx{
	echo -n $str |
	openssl dgst -$dgst -binary|
	perl -e 'print unpack "H*", join "", <>;'
    }
}

is md5($test-string).unpack('H*'), openssl('md5'), 'MD5';
is sha1($test-string).unpack('H*'), openssl('sha1'), 'SHA-1';
is sha256($test-string).unpack('H*'), openssl('sha256'), 'SHA-256';
is rmd160($test-string).unpack('H*'), openssl('rmd160'), 'RIPEMD-160';

# vim: ft=perl6
