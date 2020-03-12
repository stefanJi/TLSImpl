package section

import Content
import putUint16
import java.nio.ByteBuffer

/**
 *struct {
 *  ProtocolVersion client_version;
 *  Random random;
 *  SessionID session_id;
 *  CipherSuite cipher_suites<2..2^16-2>; // 加密算法数组的长度范围为 2~((2^16)-2)
 *  CompressionMethod compression_methods<1..2^8-1>; //压缩算法数组的长度范围为 1~((2^8)-1)
 *  select (extensions_present) {
 *    case false:
 *    struct {};
 *    case true:
 *    Extension extensions<0..2^16-1>;
 *  };
 *} section.ClientHello;
 */
class ClientHello(
    val majorVersion: Byte,
    val minorVersion: Byte,
    val tlsRandomHeader: TlsRandomHeader,
    val sessionId: ByteArray,
    val cipherSuites: ByteArray,
    val compressionMethods: ByteArray
) : Content {

    override fun data(): ByteBuffer {
        val cipherSuitesLen = cipherSuites.size
        val compressionMethodsLen = compressionMethods.size.toByte()
        return ByteBuffer.allocate(size()).apply {
            put(majorVersion)
            put(minorVersion)
            put(tlsRandomHeader.data().array())
            put(sessionId.size.toByte()) /*session id length*/
            put(sessionId)
            putUint16(cipherSuitesLen)
            put(cipherSuites)
            put(compressionMethodsLen)
            put(compressionMethods)
            put(0) /*extension length 1*/
            put(0) /*extension length 2*/
        }
    }

    override fun size(): Int = 1/*major version*/ +
            1/*minor version*/ +
            tlsRandomHeader.size() /*random length*/ + 1/*session id length*/ + sessionId.size +
            2/*cipher len uint16*/ + 1 /*compression len uint8*/ +
            cipherSuites.size + compressionMethods.size + 2 /*extension length uint16*/
}