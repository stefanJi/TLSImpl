package section

import Content
import ContentType
import getUint16
import putUint16
import java.nio.ByteBuffer

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
class TLSPlaintext(
    val contentType: ContentType,
    val majorVersion: Byte,
    val minorVersion: Byte,
    val fragment: Content
) :
    Content {
    override fun data(): ByteBuffer {
        return ByteBuffer.allocate(size()).apply {
            put(contentType.type)
            put(majorVersion)
            put(minorVersion)
            putUint16(fragment.size())
            put(fragment.data().array())
        }
    }

    override fun size(): Int = 1/*content type uint8*/ + 1/*major version uint8*/ +
            1/*minor version unit8*/ + 2/*fragment length uint16*/ + fragment.size()

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