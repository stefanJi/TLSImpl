import java.nio.ByteBuffer

interface Content {
    fun data(): ByteBuffer

    fun size(): Int
}

interface ClientFlow {
    fun ClientHello(): ByteArray
    fun Certificate(): ByteArray
    fun ClientKeyExchange(): ByteArray
    fun CertificateVerify(): ByteArray
    fun ChangeCipherSpec(): ByteArray
    fun Finished(): ByteArray
    fun ApplicationData(): ByteArray
}

interface ServerFlow {
    fun ServerHello(): ByteArray
    fun Certificate(): ByteArray
    fun ServerKeyExchange(): ByteArray
    fun CertificateRequest(): ByteArray
    fun ServerHelloDone(): ByteArray
    fun ChangeCipherSpec(): ByteArray
    fun Finished(): ByteArray
    fun ApplicationData(): ByteArray
}

/*
* TLS Version v1.2(3,3)
 */
const val TLS_VERSION_MAJOR: Byte = 3
const val TLS_VERSION_MINOR: Byte = 3

enum class ContentType(val type: Byte) {
    change_cipher_spec(20),
    alert(21),
    handshake(22),
    application_data(23)
}

/**
 * <pre>
 * struct {
 *     uint8 major;
 *     uint8 minor;
 * } ProtocolVersion;
 *
 * enum {
 *     change_cipher_spec(20), alert(21), handshake(22),
 *     application_data(23), (255)
 * } ContentType;
 *
 * struct {
 *     ContentType type;
 *     ProtocolVersion version;
 *     uint16 length;
 *     opaque fragment[TLSPlaintext.length];
 * } TLSPlaintext;
 * </pre>
 */
class TLSPlaintext(val contentType: ContentType, val majorVersion: Byte, val minorVersion: Byte, val content: Content) :
    Content {
    override fun data(): ByteBuffer {
        return ByteBuffer.allocate(size()).apply {
            put(contentType.type)
            put(majorVersion)
            put(minorVersion)
            //big-endianness 高位在前
            put((content.size() shr 8 and 0xFF).toByte())
            put((content.size() and 0xFF).toByte())
            put(content.data().array())
        }
    }

    override fun size(): Int = 1/*content type uint8*/ + 1/*major version uint8*/ +
            1/*minor version unit8*/ + 2/*content length uint16*/ + content.size()

    companion object {
        @JvmStatic
        fun parse(buffer: ByteBuffer): TLSPlaintext {
            val type = buffer.get()
            val contentType = ContentType.values().find { type == it.type }
                ?: error("Not found match ContentType. $type")
            val major = buffer.get()
            val minor = buffer.get()
            val contentLength = buffer.getUint16()
            return TLSPlaintext(contentType, major, minor, object : Content {
                override fun data() = buffer
                override fun size(): Int = contentLength
            })
        }
    }
}

/**
 *enum {
 *  hello_request(0), client_hello(1), server_hello(2),
 *  certificate(11), server_key_exchange (12),
 *  certificate_request(13), server_hello_done(14),
 *  certificate_verify(15), client_key_exchange(16),
 *  finished(20), (255)
 *} HandshakeType;
 *
 *struct {
 *  HandshakeType msg_type;    /* handshake type */
 *    uint24 length;             /* bytes in message */
 *    select (HandshakeType) {
 *    case hello_request:       HelloRequest;
 *    case client_hello:        ClientHello;
 *    case server_hello:        ServerHello;
 *    case certificate:         Certificate;
 *    case server_key_exchange: ServerKeyExchange;
 *    case certificate_request: CertificateRequest;
 *    case server_hello_done:   ServerHelloDone;
 *    case certificate_verify:  CertificateVerify;
 *    case client_key_exchange: ClientKeyExchange;
 *    case finished:            Finished;
 *  } body;
 *} Handshake;
 */
class HandshakeData(val msgType: HandshakeType, val body: Content) : Content {

    override fun data(): ByteBuffer {
        val bodyLength = body.size()
        return ByteBuffer.allocate(size()).apply {
            put(msgType.type)
            put((bodyLength shr 16 and 0xFF).toByte())
            put((bodyLength shr 8 and 0xFF).toByte())
            put((bodyLength and 0xFF).toByte())
            put(body.data().array())
        }
    }

    override fun size(): Int = 1/*msg type uint8*/ + 3 /*length uint24*/ + body.size()

    companion object {
        fun parse(buffer: ByteBuffer): HandshakeData {
            val type = buffer.get()
            val length = buffer.getUint24()
            val handshakeType = HandshakeType.values().find { it.type == type }
                ?: error("Not found match handshake type. $type")
            return HandshakeData(handshakeType, object : Content {
                override fun data() = buffer
                override fun size(): Int = length
            })
        }
    }
}

class TlsRandomHeader(val time: Int, val random: ByteArray) : Content {

    override fun data(): ByteBuffer {
        return ByteBuffer.allocate(size()).apply {
            putInt(time)
            put(random)
        }
    }

    override fun size(): Int = 4 /*gmt unit time*/ + 28 /*random*/
    override fun toString(): String {
        return "TlsRandomHeader(time=$time, random=${random.contentToString()})"
    }

    companion object {
        @JvmStatic
        fun parse(buffer: ByteBuffer): TlsRandomHeader {
            val time = buffer.getUint32()
            val random = ByteArray(28)
            buffer.get(random)
            return TlsRandomHeader(time, random)
        }
    }
}

enum class CipherSuite(val type: Int) {
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384(0xc030),
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384(0xc02c),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384(0xc028),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384(0xc024),
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA(0xc014),
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA(0xc00a),
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384(0x009f),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256(0x006b),
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA(0x0039),
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256(0xcca9),
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xcca8),
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256(0xccaa),
    Unknown(0xff85),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00c4),
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0088),
    TLS_GOSTR341001_WITH_28147_CNT_IMIT(0x0081),
    TLS_RSA_WITH_AES_256_GCM_SHA384(0x009d),
    TLS_RSA_WITH_AES_256_CBC_SHA256(0x003d),
    TLS_RSA_WITH_AES_256_CBC_SHA(0x0035),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256(0x00c0),
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA(0x0084),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256(0xc02f),
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256(0xc02b),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256(0xc027),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256(0xc023),
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA(0xc013),
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA(0xc009),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256(0x009e),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256(0x0067),
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA(0x0033),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00be),
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0045),
    TLS_RSA_WITH_AES_128_GCM_SHA256(0x009c),
    TLS_RSA_WITH_AES_128_CBC_SHA256(0x003c),
    TLS_RSA_WITH_AES_128_CBC_SHA(0x002f),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256(0x00ba),
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA(0x0041),
    TLS_ECDHE_RSA_WITH_RC4_128_SHA(0xc011),
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA(0xc007),
    TLS_RSA_WITH_RC4_128_SHA(0x0005),
    TLS_RSA_WITH_RC4_128_MD5(0x0004),
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA(0xc012),
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA(0xc008),
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016),
    TLS_RSA_WITH_3DES_EDE_CBC_SHA(0x000a),
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV(0x00ff)
}


/**
 *struct {
 * ProtocolVersion server_version;
 * Random random;
 * SessionID session_id;
 * CipherSuite cipher_suite;
 * CompressionMethod compression_method;
 * select (extensions_present) {
 *   case false:
 *     struct {};
 *   case true:
 *    Extension extensions<0..2^16-1>;
 *  };
 *} ServerHello;
 */
class ServerHello(
    var versionMajor: Byte = 0,
    var versionMinor: Byte = 0,
    val random: TlsRandomHeader,
    val session: ByteArray,
    val cipherSuites: Int = 0,
    val compressionMethods: Byte = 0,
    val extensions: ByteArray
) {

    companion object {

        @JvmStatic
        fun parse(buffer: ByteBuffer): ServerHello {
            val versionMajor = buffer.get()
            val versionMinor = buffer.get()
            val randomHeader = TlsRandomHeader.parse(buffer)
            val sessionLen = buffer.get()
            val session = ByteArray(sessionLen.toInt())
            buffer.get(session)
            val cipherSuites = buffer.getUint16()
            val compressionMethods = buffer.get()
            val extensionLength = buffer.getUint16()
            val extensions = ByteArray(extensionLength)
            buffer.get(extensions)

            return ServerHello(
                versionMajor,
                versionMinor,
                randomHeader,
                session,
                cipherSuites,
                compressionMethods,
                extensions
            )
        }
    }

    override fun toString(): String {
        return "ServerHello(versionMajor=$versionMajor, versionMinor=$versionMinor, random=$random, session=${session.contentToString()}, cipherSuites=$cipherSuites, compressionMethods=$compressionMethods, extensions=${extensions.contentToString()})"
    }

}

fun ByteBuffer.getUint16(): Int = (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.getUint24(): Int =
    (get().toInt() and 0xFF shl 16) or (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)

fun ByteBuffer.getUint32(): Int =
    (get().toInt() and 0xFF shl 24) or (get().toInt() and 0xFF shl 16) or (get().toInt() and 0xFF shl 8) or (get().toInt() and 0xFF)
