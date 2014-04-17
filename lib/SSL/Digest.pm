module SSL::Digest;
use NativeCall;

constant little-endian = True;

CHECK {
    little-endian ~~ Bool
	or die 'Please set "little-endian" constant in source code';
    # ~ ' or set the ENDIANNESS environment variable to "big" or "little".'
}

sub MD4(    CArray[uint8], Int, OpaquePointer ) returns CArray[uint32] is native('libssl') { * }
sub MD5(    CArray[uint8], Int, OpaquePointer ) returns CArray[uint32] is native('libssl') { * }
sub SHA1(   CArray[uint8], Int, OpaquePointer ) returns CArray[uint32] is native('libssl') { * }
sub SHA256( CArray[uint8], Int, OpaquePointer ) returns CArray[uint32] is native('libssl') { * }
sub RIPEMD160( CArray[uint8], Int, OpaquePointer ) returns CArray[uint32] is native('libssl') { * }

sub splitint(int $i) {
    my $n = $i < 0 ?? 256**4 + $i !! $i;
    my @a = map { $n div 256**$_ % 256 }, ^4;
    little-endian ?? @a !! reverse @a;
}

sub CArray2Buf($A, Int $length) returns Buf {
    Buf.new: map &splitint, $A[^$length];
}

sub Buf2Args($buf) {
    my $array = CArray[uint8].new();
    $array[$_] = $buf[$_] for ^$buf.bytes;
    return $array, $buf.bytes, Any;
}

proto md4($) returns Buf is export {*}
proto md5($) returns Buf is export {*}
proto sha1($) returns Buf is export {*}
proto sha256($) returns Buf is export {*}
proto rmd160($) returns Buf is export {*}

multi md4(Str $str) { md4($str.encode('utf8')) }
multi md5(Str $str) { md5($str.encode('utf8')) }
multi sha1(Str $str) { sha1($str.encode('utf8')) }
multi sha256(Str $str) { sha256($str.encode('utf8')) }
multi rmd160(Str $str) { rmd160($str.encode('utf8')) }

multi md4(Blob $buf) { CArray2Buf    MD4(    |Buf2Args($buf) ), 4 }
multi md5(Blob $buf) { CArray2Buf    MD5(    |Buf2Args($buf) ), 4 }
multi sha1(Blob $buf) { CArray2Buf   SHA1(   |Buf2Args($buf) ), 5 }
multi sha256(Blob $buf) { CArray2Buf SHA256( |Buf2Args($buf) ), 8 }
multi rmd160(Blob $buf) { CArray2Buf RIPEMD160( |Buf2Args($buf) ), 5 }

# vim: ft=perl6
