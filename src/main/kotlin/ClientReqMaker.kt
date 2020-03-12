import section.HandshakeData
import section.TLSPlaintext
import section.TlsRandomHeader
import kotlin.random.Random

/**
 * Create by StefanJi in 2020-03-10
 */
class ClientReqMaker : ClientFlow {
    var randomTime = 0
        private set
    lateinit var random: ByteArray
        private set

    fun makeClientHello(): ByteArray {
        randomTime = (System.currentTimeMillis() / 1000L).toInt()
        random = Random(10).nextBytes(28)

        fun makeCipher(): ByteArray {
            val cipherSuites = ByteArray(2/*every cipher suite 2 bytes*/ * CipherSuite.values().size)
            var index = 0
            CipherSuite.values().forEach {
                cipherSuites[index++] = (it.type shr 8 and 0xFF).toByte()
                cipherSuites[index++] = (it.type and 0xFF).toByte()
            }
            return cipherSuites
        }

        val clientHello = section.ClientHello(TLS_VERSION_MAJOR, TLS_VERSION_MINOR,
            TlsRandomHeader(randomTime, random), ByteArray(0),
            makeCipher(),
            ByteArray(1) { 0 })

        val handshakeData = HandshakeData(HandshakeType.client_hello, clientHello)
        val tlsPlaintext = TLSPlaintext(
            ContentType.handshake,
            TLS_VERSION_MAJOR,
            TLS_VERSION_MINOR,
            handshakeData
        )
        return tlsPlaintext.data().array()
    }

    override fun ClientHello(): ByteArray = makeClientHello()

    override fun Certificate(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ClientKeyExchange(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun CertificateVerify(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ChangeCipherSpec(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun Finished(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }

    override fun ApplicationData(): ByteArray {
        TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
    }
}

