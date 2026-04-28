package com.tagwriter.nfc

import android.app.PendingIntent
import android.content.Intent
import android.content.SharedPreferences
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import java.nio.charset.Charset

class MainActivity : AppCompatActivity() {

    private lateinit var nfcAdapter: NfcAdapter
    private lateinit var prefs: SharedPreferences

    private lateinit var tvEstado: TextView
    private lateinit var tvContenidoActual: TextView
    private lateinit var etGestion: EditText
    private lateinit var layoutGestion: View
    private lateinit var etPassword: EditText
    private lateinit var btnModo: Button
    private lateinit var cardContenido: View

    private enum class Modo { LEER, ESCRIBIR }
    private var modoActual = Modo.LEER
    private var textoActual = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences("tagwriter", MODE_PRIVATE)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)

        tvEstado          = findViewById(R.id.tvEstado)
        tvContenidoActual = findViewById(R.id.tvContenidoActual)
        etGestion         = findViewById(R.id.etGestionInput)
        layoutGestion     = findViewById(R.id.layoutGestion)
        etPassword        = findViewById(R.id.etPassword)
        btnModo           = findViewById(R.id.btnModo)
        cardContenido     = findViewById(R.id.cardContenido)

        etPassword.setText(prefs.getString("password", ""))

        btnModo.setOnClickListener {
            cambiarModo(if (modoActual == Modo.LEER) Modo.ESCRIBIR else Modo.LEER)
        }

        findViewById<Button>(R.id.btnGuardarPwd).setOnClickListener {
            prefs.edit().putString("password", etPassword.text.toString()).apply()
            Toast.makeText(this, "Contrasena guardada", Toast.LENGTH_SHORT).show()
        }

        cambiarModo(Modo.LEER)
    }

    override fun onResume() {
        super.onResume()
        val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
        val pi = PendingIntent.getActivity(this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE)
        nfcAdapter.enableForegroundDispatch(this, pi, null, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter.disableForegroundDispatch(this)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val tag = intent.getParcelableExtra<Tag>(NfcAdapter.EXTRA_TAG) ?: return
        when (modoActual) {
            Modo.LEER     -> leerTag(tag)
            Modo.ESCRIBIR -> escribirTag(tag)
        }
    }

    private fun leerTag(tag: Tag) {
        try {
            val ndef = Ndef.get(tag) ?: run {
                runOnUiThread { mostrarEstado("Tag no compatible con NDEF", verde = false) }
                return
            }
            ndef.connect()
            val message = ndef.ndefMessage
            ndef.close()

            if (message != null && message.records.isNotEmpty()) {
                textoActual = parsearTexto(message.records[0])
                runOnUiThread {
                    tvContenidoActual.text = textoActual
                    cardContenido.visibility = View.VISIBLE
                    mostrarEstado("Tag leido - acerca de nuevo para escribir", verde = true)
                    cambiarModo(Modo.ESCRIBIR)
                }
            } else {
                runOnUiThread { mostrarEstado("Tag vacio", verde = false) }
            }
        } catch (e: Exception) {
            runOnUiThread { mostrarEstado("Error al leer: ${e.message}", verde = false) }
        }
    }

    private fun escribirTag(tag: Tag) {
        val linea = etGestion.text.toString().trim()
        if (linea.isEmpty()) {
            runOnUiThread { mostrarEstado("Escribe la linea de gestion primero", verde = false) }
            return
        }

        val passwordHex = etPassword.text.toString().trim()
        val pwd: ByteArray? = if (passwordHex.length == 8) hexToBytes(passwordHex) else null

        Thread {
            try {
                val mifare = MifareUltralight.get(tag) ?: throw Exception("Tag no compatible")
                mifare.connect()

                if (pwd != null) {
                    if (!pwdAuth(mifare, pwd)) {
                        mifare.close()
                        runOnUiThread { mostrarEstado("Contrasena incorrecta", verde = false) }
                        return@Thread
                    }
                    setAuth0(mifare, 0xFF.toByte())
                }

                val nuevoTexto = if (textoActual.isNotEmpty()) "$textoActual $linea" else linea
                escribirNDEF(mifare, nuevoTexto)

                if (pwd != null) {
                    setAuth0(mifare, 0x04.toByte())
                    setPassword(mifare, pwd)
                }

                mifare.close()

                runOnUiThread {
                    mostrarEstado("Tag escrito correctamente en 1 tap!", verde = true)
                    etGestion.setText("")
                    textoActual = nuevoTexto
                    tvContenidoActual.text = nuevoTexto
                    cambiarModo(Modo.LEER)
                }
            } catch (e: Exception) {
                runOnUiThread { mostrarEstado("Error: ${e.message}", verde = false) }
            }
        }.start()
    }

    private fun pwdAuth(tag: MifareUltralight, pwd: ByteArray): Boolean {
        return try {
            val resp = tag.transceive(byteArrayOf(0x1B.toByte()) + pwd)
            resp != null && resp.size >= 2
        } catch (e: Exception) { false }
    }

    private fun setAuth0(tag: MifareUltralight, value: Byte) {
        try {
            val page = tag.transceive(byteArrayOf(0x30.toByte(), 0x29.toByte()))
            val data = if (page != null && page.size >= 4)
                byteArrayOf(page[0], page[1], page[2], value)
            else byteArrayOf(0, 0, 0, value)
            tag.transceive(byteArrayOf(0xA2.toByte(), 0x29.toByte()) + data)
        } catch (e: Exception) {}
    }

    private fun setPassword(tag: MifareUltralight, pwd: ByteArray) {
        try {
            tag.transceive(byteArrayOf(0xA2.toByte(), 0x2B.toByte()) + pwd)
            tag.transceive(byteArrayOf(0xA2.toByte(), 0x2C.toByte(), 0, 0, 0, 0))
        } catch (e: Exception) {}
    }

    private fun escribirNDEF(tag: MifareUltralight, texto: String) {
        val lang = "es".toByteArray(Charsets.US_ASCII)
        val textBytes = texto.toByteArray(Charsets.UTF_8)
        val payload = byteArrayOf(lang.size.toByte()) + lang + textBytes

        val record = NdefRecord(NdefRecord.TNF_WELL_KNOWN, NdefRecord.RTD_TEXT, ByteArray(0), payload)
        val ndefBytes = ndefToBytes(NdefMessage(arrayOf(record)))

        val tlv = byteArrayOf(0x03.toByte(), ndefBytes.size.toByte()) +
                  ndefBytes + byteArrayOf(0xFE.toByte())
        val rem = tlv.size % 4
        val padded = if (rem == 0) tlv else tlv + ByteArray(4 - rem)

        for (i in 0 until padded.size / 4) {
            val chunk = padded.copyOfRange(i * 4, i * 4 + 4)
            tag.transceive(byteArrayOf(0xA2.toByte(), (4 + i).toByte()) + chunk)
        }
    }

    private fun ndefToBytes(msg: NdefMessage): ByteArray {
        var out = ByteArray(0)
        msg.records.forEachIndexed { i, r ->
            var f = (0x10 or (r.tnf.toInt() and 0x07)).toByte()
            if (i == 0) f = (f.toInt() or 0x80).toByte()
            if (i == msg.records.size - 1) f = (f.toInt() or 0x40).toByte()
            out += byteArrayOf(f, r.type.size.toByte(), r.payload.size.toByte())
            out += r.type + r.payload
        }
        return out
    }

    private fun parsearTexto(record: NdefRecord): String {
        return try {
            val p = record.payload
            val enc = if (p[0].toInt() and 0x80 != 0) "UTF-16" else "UTF-8"
            val langLen = p[0].toInt() and 0x3F
            String(p, 1 + langLen, p.size - 1 - langLen, Charset.forName(enc))
        } catch (e: Exception) { "" }
    }

    private fun hexToBytes(hex: String): ByteArray? = try {
        ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    } catch (e: Exception) { null }

    private fun cambiarModo(modo: Modo) {
        modoActual = modo
        when (modo) {
            Modo.LEER -> {
                btnModo.text = "Modo: LEER TAG"
                btnModo.setBackgroundColor(ContextCompat.getColor(this, R.color.azul))
                tvEstado.text = "Acerca el tag para leer su contenido"
                layoutGestion.visibility = View.GONE
            }
            Modo.ESCRIBIR -> {
                btnModo.text = "Modo: ESCRIBIR TAG"
                btnModo.setBackgroundColor(ContextCompat.getColor(this, R.color.verde))
                tvEstado.text = "Escribe la linea de gestion y acerca el tag"
                layoutGestion.visibility = View.VISIBLE
            }
        }
    }

    private fun mostrarEstado(msg: String, verde: Boolean) {
        tvEstado.text = msg
        tvEstado.setTextColor(ContextCompat.getColor(this, if (verde) R.color.verde else R.color.rojo))
    }
}
