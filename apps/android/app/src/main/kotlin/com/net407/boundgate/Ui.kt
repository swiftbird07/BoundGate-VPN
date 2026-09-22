package com.net407.boundgate

import android.content.Context
import android.content.res.Configuration
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.RippleDrawable
import android.content.res.ColorStateList
import android.text.InputType
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** The tokens of docs/DESIGN.md (Theme.swift, web/src/app.css), for both appearances. */
class Theme(val dark: Boolean) {
    val bg = if (dark) 0xFF1D1D1D.toInt() else 0xFFF4F2EB.toInt()
    val panel = if (dark) 0xFF2A2A2A.toInt() else 0xFFFFFFFF.toInt()
    val panel2 = if (dark) 0xFF343434.toInt() else 0xFFF0EDE4.toInt()
    val panel3 = if (dark) 0xFF3E3E3E.toInt() else 0xFFE6E2D6.toInt()
    val border = if (dark) 0x14FFFFFF else 0x1A2A2A2A
    val borderStrong = if (dark) 0x2BFFFFFF else 0x3D2A2A2A
    val text = if (dark) 0xFFF5F2EA.toInt() else 0xFF2A2A2A.toInt()
    val text2 = if (dark) 0xFFB9B4A8.toInt() else 0xFF5D594F.toInt()
    val text3 = if (dark) 0xFF868074.toInt() else 0xFF8B8678.toInt()
    val ok = if (dark) 0xFF5FD38D.toInt() else 0xFF178A4A.toInt()
    val warn = if (dark) 0xFFFF9F45.toInt() else 0xFFC2560A.toInt()
    val bad = if (dark) 0xFFFF6B6B.toInt() else 0xFFCF3030.toInt()
    val logoGround = if (dark) ACCENT else CHARCOAL
    val logoMark = if (dark) CHARCOAL else ACCENT

    companion object {
        const val ACCENT = 0xFFFFCC00.toInt()
        const val ACCENT_HI = 0xFFFFD83D.toInt()
        const val CHARCOAL = 0xFF2A2A2A.toInt()
        const val ON_ACCENT = CHARCOAL

        fun of(c: Context) = Theme((c.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES)
    }
}

enum class Tone { OK, ACCENT, IDLE, WARN, BAD }

/** Builds the screen's pieces; sizes in dp and sp as in the iOS app (MobileView). */
class Ui(val c: Context, val t: Theme) {
    private val density = c.resources.displayMetrics.density
    fun dp(v: Float) = (v * density + 0.5f).toInt()
    fun dp(v: Int) = dp(v.toFloat())

    // the rounded display face of the other apps is not on Android; its bold sans stands in
    val display: Typeface = Typeface.create("sans-serif", Typeface.BOLD)
    val body: Typeface = Typeface.create("sans-serif", Typeface.NORMAL)
    val medium: Typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
    val mono: Typeface = Typeface.MONOSPACE

    fun rounded(fill: Int, radius: Float, stroke: Int = 0) = GradientDrawable().apply {
        setColor(fill)
        cornerRadius = dp(radius).toFloat()
        if (stroke != 0) setStroke(maxOf(1, dp(1f) / 2 + 1), stroke)
    }

    fun column(spacing: Int = 10) = LinearLayout(c).apply {
        orientation = LinearLayout.VERTICAL
        showDividers = LinearLayout.SHOW_DIVIDER_MIDDLE
        dividerDrawable = GradientDrawable().apply { setSize(1, dp(spacing)); setColor(Color.TRANSPARENT) }
    }

    fun row() = LinearLayout(c).apply {
        orientation = LinearLayout.HORIZONTAL
        gravity = Gravity.CENTER_VERTICAL
    }

    /** A card: the panel surface, 14 dp corners, a hairline border. */
    fun card(vararg children: View) = column().apply {
        background = rounded(t.panel, 14f, t.border)
        setPadding(dp(16), dp(16), dp(16), dp(16))
        children.forEach { addView(it, fill()) }
    }

    fun fill() = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT)

    fun text(s: String, size: Float, color: Int, face: Typeface = body) = TextView(c).apply {
        text = s
        setTextColor(color)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        typeface = face
        setLineSpacing(0f, 1.15f)
    }

    fun title(s: String) = text(s, 17f, t.text, display)
    fun para(s: String) = text(s, 14f, t.text2)

    /** Primary: yellow fill, charcoal text. Secondary: surface step with a border. Danger: red text. */
    fun button(label: String, kind: String = "secondary", enabled: Boolean = true, onClick: () -> Unit) = TextView(c).apply {
        text = label
        gravity = Gravity.CENTER
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        typeface = medium
        setPadding(dp(18), dp(13), dp(18), dp(13))
        setTextColor(
            when (kind) {
                "primary" -> Theme.ON_ACCENT
                "danger" -> t.bad
                else -> t.text
            },
        )
        val fill = if (kind == "primary") rounded(Theme.ACCENT, 10f) else rounded(t.panel2, 10f, t.border)
        background = RippleDrawable(ColorStateList.valueOf(if (kind == "primary") Theme.ACCENT_HI else t.panel3), fill, null)
        isEnabled = enabled
        alpha = if (enabled) 1f else 0.5f
        isClickable = enabled
        if (enabled) setOnClickListener { onClick() }
    }

    fun pill(s: String, tone: Tone) = text(s, 12.5f, toneText(tone), medium).apply {
        setPadding(dp(10), dp(4), dp(10), dp(4))
        background = rounded(toneFill(tone), 100f)
    }

    fun notice(tone: Tone, s: String) = text(s, 13.5f, if (tone == Tone.ACCENT) t.text else toneColor(tone)).apply {
        setPadding(dp(12), dp(10), dp(12), dp(10))
        background = rounded(toneFill(tone), 10f)
        setTextIsSelectable(true)
    }

    fun toneColor(tone: Tone) = when (tone) {
        Tone.OK -> t.ok
        Tone.ACCENT -> Theme.ACCENT
        Tone.IDLE -> t.text3
        Tone.WARN -> t.warn
        Tone.BAD -> t.bad
    }

    private fun toneText(tone: Tone) = when (tone) {
        Tone.ACCENT -> if (t.dark) Theme.ACCENT else t.text
        Tone.IDLE -> t.text2
        else -> toneColor(tone)
    }

    private fun toneFill(tone: Tone): Int {
        val a = if (tone == Tone.ACCENT) (if (t.dark) 0x1F else 0x40) else 0x1F
        return (toneColor(tone) and 0x00FFFFFF) or (a shl 24)
    }

    /** Label on the left, value on the right, as InfoRow. */
    fun info(label: String, value: String, monoValue: Boolean = false) = row().apply {
        gravity = Gravity.TOP
        addView(text(label, 14f, t.text3), LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.9f))
        addView(
            text(value, 14f, t.text, if (monoValue) mono else body).apply {
                gravity = Gravity.END
                setTextIsSelectable(true)
            },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 2f),
        )
    }

    /** A fingerprint in groups of four, monospaced, selectable. */
    fun fingerprint(title: String, fp: String) = column(6).apply {
        addView(text(title, 12.5f, t.text3, medium), fill())
        val groups = fp.replace(" ", "").chunked(4)
        addView(
            text(groups.chunked(4).joinToString("\n") { it.joinToString("  ") }, 15f, t.text, mono).apply {
                setPadding(dp(12), dp(10), dp(12), dp(10))
                background = rounded(t.panel2, 10f, t.border)
                setTextIsSelectable(true)
                setLineSpacing(0f, 1.3f)
            },
            fill(),
        )
    }

    fun field(hint: String, value: String, monoText: Boolean, lowercase: Boolean, onChange: (String) -> Unit) = EditText(c).apply {
        setText(value)
        this.hint = hint
        setHintTextColor(t.text3)
        setTextColor(t.text)
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 16f)
        typeface = if (monoText) mono else body
        isSingleLine = true
        inputType = if (lowercase) {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        } else {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_WORDS
        }
        setPadding(dp(12), dp(11), dp(12), dp(11))
        background = rounded(t.panel2, 10f, t.borderStrong)
        addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, d: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                val v = s?.toString() ?: ""
                // the control plane's name: lowercase as it is typed (pins and SNI are exact)
                if (lowercase && v != v.lowercase()) {
                    s?.replace(0, s.length, v.lowercase())
                    return
                }
                onChange(v)
            }
        })
    }
}

/** The mark on its tile (Mark.swift, LogoTile): two interlocked rounded frames on a 1024 grid. */
class LogoTile(c: Context, private val t: Theme) : View(c) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val path = Path()
    private val r = RectF()

    override fun onDraw(canvas: Canvas) {
        val size = minOf(width, height).toFloat()
        val s = size / 1024f
        paint.style = Paint.Style.FILL
        paint.color = t.logoGround
        r.set(0f, 0f, size, size)
        canvas.drawRoundRect(r, 232 * s, 232 * s, paint)
        paint.style = Paint.Style.STROKE
        paint.strokeWidth = 57 * s
        paint.strokeCap = Paint.Cap.ROUND
        paint.strokeJoin = Paint.Join.ROUND
        paint.color = t.logoMark
        path.reset()
        for ((x, y) in listOf(148f to 268f, 414f to 456f)) {
            r.set(x * s, y * s, (x + 462) * s, (y + 300) * s)
            path.addRoundRect(r, 76 * s, 76 * s, Path.Direction.CW)
        }
        canvas.drawPath(path, paint)
    }
}
