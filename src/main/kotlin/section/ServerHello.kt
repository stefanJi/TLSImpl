package section

import getUint16
import java.nio.ByteBuffer

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
 *} section.ServerHello;
 */
class ServerHello(
    var versionMajor: Byte = 0,
    var versionMinor: Byte = 0,
    val random: TlsRandomHeader,
    val session: ByteArray,
    val cipherSuites: Int = 0,
    val compressionMethods: Byte = 0,
    val extensions: HelloExtension
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
            val extensions = HelloExtension.parse(buffer)
            println("version: $versionMajor,$versionMinor")
            println("extensions: $extensions")

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
}