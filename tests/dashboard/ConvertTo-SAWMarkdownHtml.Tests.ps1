BeforeAll {
    . "$PSScriptRoot/../../src/dashboard/ConvertTo-SAWMarkdownHtml.ps1"
}

Describe 'ConvertTo-SAWMarkdownHtml' {
    It 'returns an empty string for empty input' {
        ConvertTo-SAWMarkdownHtml -Markdown '' | Should -Be ''
    }

    It 'converts ATX headers of every level used (h1-h3) to the matching tag' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown "# Title`n## Section`n### Subsection"

        $html | Should -Match '<h1>Title</h1>'
        $html | Should -Match '<h2>Section</h2>'
        $html | Should -Match '<h3>Subsection</h3>'
    }

    It 'wraps a blank-line-separated block of text in a single <p>' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown "First line.`nSecond line."

        $html | Should -Be '<p>First line. Second line.</p>'
    }

    It 'starts a new paragraph after a blank line' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown "Para one.`n`nPara two."

        $html | Should -Be "<p>Para one.</p>`n<p>Para two.</p>"
    }

    It 'converts a bullet list (- marker) to <ul><li>' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown "- First`n- Second"

        $html | Should -Be '<ul><li>First</li><li>Second</li></ul>'
    }

    It 'converts a numbered list to <ol><li>' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown "1. First`n2. Second"

        $html | Should -Be '<ol><li>First</li><li>Second</li></ol>'
    }

    It 'appends a soft-wrapped continuation line to the current list item instead of starting a stray paragraph' {
        # Real bug this guards against: docs/reading-the-report.md wraps long list items across
        # multiple source lines (indented continuation, no blank line) - the first version of
        # this converter treated the continuation as a new paragraph, cutting items off
        # mid-sentence in the rendered dashboard tab.
        $html = ConvertTo-SAWMarkdownHtml -Markdown "- First part of the item`n  continues here."

        $html | Should -Be '<ul><li>First part of the item continues here.</li></ul>'
    }

    It 'converts a GFM pipe table with header separator to a Bootstrap table' {
        $md = "| A | B |`n|---|---|`n| 1 | 2 |"

        $html = ConvertTo-SAWMarkdownHtml -Markdown $md

        $html | Should -Match '<table'
        $html | Should -Match '<th>A</th><th>B</th>'
        $html | Should -Match '<td>1</td><td>2</td>'
        $html | Should -Not -Match '\|---\|'
    }

    It 'converts **bold**, *italic*, `code`, and [text](url) links inline' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown 'A **bold** and *italic* and `code` and [a link](https://example.com).'

        $html | Should -Match '<strong>bold</strong>'
        $html | Should -Match '<em>italic</em>'
        $html | Should -Match '<code>code</code>'
        $html | Should -Match '<a href="https://example.com" target="_blank" rel="noopener noreferrer">a link</a>'
    }

    It 'HTML-encodes literal <, >, and & before applying any markup' {
        $html = ConvertTo-SAWMarkdownHtml -Markdown 'Use <script> & "quotes" here.'

        $html | Should -Match '&lt;script&gt;'
        $html | Should -Match '&amp;'
        $html | Should -Not -Match '<script>'
    }

    It 'loads and converts the real bundled docs/reading-the-report.md without error' {
        $realPath = "$PSScriptRoot/../../docs/reading-the-report.md"
        $markdown = Get-Content -Path $realPath -Raw

        $html = ConvertTo-SAWMarkdownHtml -Markdown $markdown

        $html | Should -Match '<h1>'
        $html | Should -Match '<table'
        $html | Should -Match '<ol>'
        $html | Should -Match '<ul>'
        # No stray truncated list items: every <li> should end with the closing tag right after
        # real content, not get interrupted by a stray </ul><p> mid-sentence for a wrapped line.
        $html | Should -Not -Match '</ul>\s*$'
    }
}
