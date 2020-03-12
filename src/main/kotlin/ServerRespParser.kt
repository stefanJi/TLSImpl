import section.HandshakeData
import section.ServerHello
import section.TLSPlaintext
import java.io.OutputStream
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-10
 */
class ServerRespParser(private val outs: OutputStream) {
    private var compressionMethod: Byte = 0
    private var cipherSuite: Int = 0
    private var randomTime: Int = 0
    private lateinit var random: ByteArray

    fun parse(data: ByteArray) {
        if (data.isEmpty()) {
            throw IllegalArgumentException("")
        }
        println("Received bytes: ${data.size}")

        val buffer = ByteBuffer.wrap(data)
        var offset = 0
        while (offset < data.size) {
            val tlsPlaintext = TLSPlaintext.parse(buffer)
            offset += tlsPlaintext.size()
            println("tls plaint length: ${tlsPlaintext.size()}")
            when (tlsPlaintext.contentType) {
                ContentType.handshake -> {
                    handleHandshake(tlsPlaintext.fragment.data())
                }
                ContentType.change_cipher_spec -> {
                }
                ContentType.alert -> {
                }
                ContentType.application_data -> {
                }
            }
        }
    }

    private fun handleHandshake(buffer: ByteBuffer) {
        val handshakeData = HandshakeData.parse(buffer)
        val handshakeType = handshakeData.msgType
        val length = handshakeData.body.size()
        println("handshake data type: $handshakeType length: $length")
        val content = handshakeData.body.data()

        when (handshakeType) {
            HandshakeType.server_hello -> {
                handleServerHello(content)
            }
            HandshakeType.certificate -> {
                handleCertificate(content)
            }
            HandshakeType.server_key_exchange -> {
                handleServerKeyExchange(content)
            }
            HandshakeType.certificate_request -> {
            }
            HandshakeType.server_hello_done -> {
                handleServerHelloDone(content)
            }
            HandshakeType.certificate_verify -> {
                println("certificate verify")
            }
            HandshakeType.finished -> {
                println("finished")
            }
        }
    }

    private fun handleAlert(buffer: ByteBuffer) {}

    private fun handleApplicationData(buffer: ByteBuffer) {}

    private fun handleChangeCipherSpce(buffer: ByteBuffer) {}

    //region handle handshake
    private fun handleServerHello(buffer: ByteBuffer) {
        println("handle server hello")
        val serverHello = ServerHello.parse(buffer)
    }

    private fun handleCertificate(buffer: ByteBuffer) {
        println("handle certificate")
        val certificatesLength = buffer.getUint24()
        println("certificate length: $certificatesLength")
        var offset = 0
        var index = 0
        while (offset < certificatesLength) {
            val certificateLength = buffer.getUint24()
            val certificate = ByteArray(certificateLength)
            println("certificate #$index len: $certificateLength")
            buffer.get(certificate)
            offset += 3 /*uint24 certificate length*/
            offset += certificateLength
        }
    }

    private fun handleServerKeyExchange(buffer: ByteBuffer) {
        println("handle server key exchange")
        val curveType = buffer.get()
        val namedCurve = ByteArray(2).also { buffer.get(it) }
        val publicKeyLength = buffer.get()
        val publicKey = ByteArray(publicKeyLength.toInt()).also { buffer.get(it) }
        val signatureHashAlgorithmHash = buffer.get()
        val signatureHashAlgorithmSignature = buffer.get()
        val signatureLength = buffer.getUint16()
        val signature = ByteArray(signatureLength).also { buffer.get(it) }
    }

    private fun handleServerHelloDone(byteBuffer: ByteBuffer) {
        println("handle server hello done")
    }
    //endregion
}
