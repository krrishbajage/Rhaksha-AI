package com.raksha.ai.notification

object UrlExtractor {

    private val URL_PATTERN = Regex(
        """https?://[^\s<>"{}|\\^`\[\]]+""",
        RegexOption.IGNORE_CASE
    )

    fun extract(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        return URL_PATTERN.findAll(text)
            .map { it.value.trimEnd('.', ',', ';', ')', ']', '"', '\'') }
            .distinct()
            .toList()
    }
}
