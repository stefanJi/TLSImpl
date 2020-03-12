package section

import Content
import getUint16
import putUint16
import java.nio.ByteBuffer

/**
 * Create by StefanJi in 2020-03-12
 */
class HelloExtension(
    val length: Int,
    val extensions: Array<Extension>
) : Content {

    class Extension(val type: Int, val length: Int, val data: ByteArray) : Content {
        override fun data() = ByteBuffer.allocate(size()).apply {
            putUint16(type)
            putUint16(data.size)
            put(data)
        }

        override fun size(): Int = 2 /*type: uint16*/ + 2 /*len uint16*/ + data.size

        override fun toString(): String {
            return "Extension(type=$type, length=$length, data=${data.contentToString()})"
        }

        companion object {
            fun parse(buffer: ByteBuffer): Extension {
                val type = buffer.getUint16()
                val len = buffer.getUint16()
                val data = ByteArray(len)
                buffer.get(data)
                return Extension(type, len, data)
            }
        }
    }

    override fun data(): ByteBuffer = ByteBuffer.allocate(size()).apply {
        val extensionLength = extensions.sumBy { it.size() }
        putUint16(extensionLength)
        extensions.forEach { put(it.data().array()) }
    }

    override fun size(): Int = 2/* extension_data length: uint_16 */ +
            extensions.sumBy { it.size() }

    override fun toString(): String {
        return "HelloExtension(length=$length, extensions=${extensions.contentToString()})"
    }

    companion object {

        fun parse(buffer: ByteBuffer): HelloExtension {
            val length = buffer.getUint16()
            var offset = 0
            val extensions = arrayListOf<Extension>()
            while (offset < length) {
                val extension = Extension.parse(buffer)
                offset += extension.size()
                extensions.add(extension)
            }
            return HelloExtension(length, extensions.toTypedArray())
        }
    }


}