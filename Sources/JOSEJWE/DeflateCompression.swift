#if canImport(CZlib)
    import CZlib
    import Foundation

    /// Raw DEFLATE (RFC 1951), the `zip` value `DEF`: no zlib header and no checksum. zlib
    /// produces and reads that when given negative window bits.
    ///
    /// zlib is used on every platform that has it as a system library, Apple's included, where it
    /// ships with the operating system. Apple's Compression framework also does raw DEFLATE, but it
    /// silently discards input after the end of the stream, which zlib (and the browsers'
    /// DecompressionStream that panva/jose uses) refuses; one implementation keeps every platform's
    /// behaviour the same. Windows has no system zlib, so this type does not exist there.
    struct DeflateCompression: CompressionAlgorithm {
        /// The output buffer each step writes into. Decompression stops within one buffer of the
        /// limit, so this also bounds how far past the limit memory use can go.
        let chunkSize = 64 * 1024

        func compress(_ data: Data) throws(CompressionError) -> Data {
            try process(data, encoding: true, limit: Int.max)
        }

        func decompress(_ data: Data, limit: Int) throws(CompressionError) -> Data {
            try process(data, encoding: false, limit: limit)
        }

        private func process(_ input: Data, encoding: Bool, limit: Int) throws(CompressionError) -> Data {
            guard input.count <= Int(UInt32.max) else {
                throw .tooLarge
            }
            var bytes = [UInt8](input)
            let result: Result<Data, CompressionError> = bytes.withUnsafeMutableBufferPointer { source in
                run(source, encoding: encoding, limit: limit)
            }
            return try result.get()
        }

        private func run(
            _ source: UnsafeMutableBufferPointer<UInt8>,
            encoding: Bool,
            limit: Int
        ) -> Result<Data, CompressionError> {
            let destination = UnsafeMutablePointer<UInt8>.allocate(capacity: chunkSize)
            defer { destination.deallocate() }

            var stream = z_stream()
            let streamSize = Int32(MemoryLayout<z_stream>.size)
            // Negative window bits select raw DEFLATE, with no zlib header or checksum.
            var status: Int32
            if encoding {
                status = deflateInit2_(
                    &stream,
                    Z_DEFAULT_COMPRESSION,
                    Z_DEFLATED,
                    -MAX_WBITS,
                    8,
                    Z_DEFAULT_STRATEGY,
                    zlibVersion(),
                    streamSize
                )
            } else {
                status = inflateInit2_(&stream, -MAX_WBITS, zlibVersion(), streamSize)
            }
            guard status == Z_OK else {
                return .failure(.failed)
            }
            defer {
                if encoding {
                    deflateEnd(&stream)
                } else {
                    inflateEnd(&stream)
                }
            }
            stream.next_in = source.baseAddress
            stream.avail_in = UInt32(source.count)

            var output = Data()
            while true {
                stream.next_out = destination
                stream.avail_out = UInt32(chunkSize)
                if encoding {
                    status = deflate(&stream, Z_FINISH)
                } else {
                    status = inflate(&stream, Z_NO_FLUSH)
                }
                let produced = chunkSize - Int(stream.avail_out)
                output.append(destination, count: produced)
                guard output.count <= limit else {
                    return .failure(.tooLarge)
                }
                switch status {
                case Z_STREAM_END:
                    // Anything after the end of the stream is not part of it.
                    guard stream.avail_in == 0 else {
                        return .failure(.malformed)
                    }
                    return .success(output)
                case Z_OK:
                    continue
                default:
                    // Z_BUF_ERROR here means the input ended before the stream did.
                    if encoding {
                        return .failure(.failed)
                    }
                    return .failure(.malformed)
                }
            }
        }
    }
#endif
