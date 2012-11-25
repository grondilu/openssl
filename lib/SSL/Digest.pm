module SSL::Digest;
use NativeCall;

constant little-endian = True;

CHECK {
    little-endian ~~ Bool
	or die 'Please set "little-endian" constant in source code';
    # ~ ' or set the ENDIANNESS environment variable to "big" or "little".'
}

sub MD4(    Str is encoded('utf8'), Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub MD5(    Str is encoded('utf8'), Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub SHA1(   Str is encoded('utf8'), Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub SHA256( Str is encoded('utf8'), Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub RIPEMD160( Str is encoded('utf8'), Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }

sub splitint(int $i) {
    my $n = $i < 0 ?? 256**4 + $i !! $i;
    my @a = map { $n div 256**$_ % 256 }, ^4;
    little-endian ?? @a !! reverse @a;
}

sub CArray2Buf($A, Int $length) returns Buf {
    Buf.new: map &splitint, $A[^$length];
}

proto md4($) returns Buf is export {*}
proto md5($) returns Buf is export {*}
proto sha1($) returns Buf is export {*}
proto sha256($) returns Buf is export {*}
proto rmd160($) returns Buf is export {*}

multi md4(Str $str) { CArray2Buf MD4( $str, $str.encode('utf8').bytes, Any ), 4 }
multi md5(Str $str) { CArray2Buf MD5( $str, $str.encode('utf8').bytes, Any ), 4 }
multi sha1(Str $str) { CArray2Buf SHA1( $str, $str.encode('utf8').bytes, Any ), 5 }
multi sha256(Str $str) { CArray2Buf SHA256( $str, $str.encode('utf8').bytes, Any ), 8 }
multi rmd160(Str $str) { CArray2Buf RIPEMD160( $str, $str.encode('utf8').bytes, Any ), 5 }

# vim: ft=perl6
