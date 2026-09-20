package com.raksha.ai.notification

object UrlExtractor {

    const val MAX_URLS = 10

    private val URL_PATTERN = Regex(
        """https?://[^\s<>"{}|\\^`\[\]]+""",
        RegexOption.IGNORE_CASE
    )

    fun extract(text: String): List<String> {
        if (text.isBlank()) return emptyList()
        return URL_PATTERN.findAll(text)
            .map { it.value.trimEnd('.', ',', ';', ')', ']', '"', '\'') }
            .distinct()
            .take(MAX_URLS)
            .toList()
    }
}
