package section

import Content
import getUint32
import java.nio.ByteBuffer

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