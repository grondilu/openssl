module SSL::Digest;
use NativeCall;

constant little-endian = True;

CHECK {
    little-endian ~~ Bool
	or die 'Please set "little-endian" constant in source code';
    # ~ ' or set the ENDIANNESS environment variable to "big" or "little".'
}

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

our sub md5(Str $s) returns Buf is export {
    CArray2Buf MD5( $s, $s.chars , Any ), 4;
}
our sub sha1(Str $s) returns Buf is export {
    CArray2Buf SHA1( $s, $s.chars , Any ), 5;
}
our sub rmd160(Str $s) returns Buf is export {
    CArray2Buf RIPEMD160( $s, $s.chars , Any ), 5;
}
our sub sha256(Str $s) returns Buf is export {
    CArray2Buf SHA256( $s, $s.chars , Any ), 8;
}

# vim: ft=perl6
