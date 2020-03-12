package section

import Content
import HandshakeType
import getUint24
import putUint24
import java.nio.ByteBuffer

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
 *    case client_hello:        section.ClientHello;
 *    case server_hello:        section.ServerHello;
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
            putUint24(bodyLength)
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