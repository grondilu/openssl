module SSL::Digest;
use NativeCall;

constant little-endian = True;

CHECK {
    little-endian ~~ Bool
	or die 'Please set "little-endian" constant in source code';
    # ~ ' or set the ENDIANNESS environment variable to "big" or "little".'
}

sub MD4(       Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub MD5(       Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub SHA1(      Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub SHA256(    Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }
sub RIPEMD160( Str, Int, OpaquePointer ) returns CArray[int] is native('libssl') { * }

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

multi md4(Str $s) { CArray2Buf MD4( $s, $s.chars , Any ), 4 }
multi md5(Str $s) { CArray2Buf MD5( $s, $s.chars , Any ), 4 }
multi sha1(Str $s) { CArray2Buf SHA1( $s, $s.chars , Any ), 5 }
multi sha256(Str $s) { CArray2Buf SHA256( $s, $s.chars , Any ), 8 }
multi rmd160(Str $s) { CArray2Buf RIPEMD160( $s, $s.chars , Any ), 5 }

multi md4(Buf $b) { md4( [~] map &chr, $b.list ) }
multi md5(Buf $b) { md5( [~] map &chr, $b.list ) }
multi sha1(Buf $b) { sha1( [~] map &chr, $b.list ) }
multi sha256(Buf $b) { sha256( [~] map &chr, $b.list ) }
multi rmd160(Buf $b) { rmd160( [~] map &chr, $b.list ) }

# vim: ft=perl6
