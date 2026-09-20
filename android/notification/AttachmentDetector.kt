package com.raksha.ai.notification

object AttachmentDetector {

    const val MAX_ATTACHMENTS = 10

    private val RISKY_FILENAME_PATTERN = Regex(
        """\b[\w.-]+\.(?:apk|exe|jar|js|bat|scr)\b""",
        RegexOption.IGNORE_CASE
    )

    fun detect(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        return RISKY_FILENAME_PATTERN.findAll(text)
            .map { it.value }
            .distinct()
            .take(MAX_ATTACHMENTS)
            .toList()
    }
}
