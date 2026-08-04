function ConvertTo-SAWMarkdownHtml {
    <#
    .SYNOPSIS
        Converts a small, deliberately scoped subset of Markdown to an HTML fragment.
    .DESCRIPTION
        Not a general-purpose Markdown parser - this exists solely to embed
        docs/reading-the-report.md as a dashboard tab (see Export-SAWDashboard.ps1's
        -ReadingGuideHtml) without pulling in an external Markdown library, so it covers exactly
        the constructs that document actually uses: ATX headers (# through ######), paragraphs,
        bullet lists (- or *), numbered lists (1. 2. ...), GFM-style pipe tables, and inline
        **bold**, `code`, and [text](url) links. Anything else (nested lists, blockquotes,
        fenced code blocks, images) is treated as plain paragraph text rather than throwing, so
        an unexpected future doc edit degrades gracefully instead of breaking dashboard
        generation entirely.

        A soft-wrapped continuation line inside a list item (no blank line, same as CommonMark)
        is appended to that item rather than starting a stray paragraph - this is exactly how
        docs/reading-the-report.md is actually formatted, so it matters for real output, not
        just theoretical correctness.

        All text content is HTML-encoded before any markup is layered on top, so this is safe
        against a doc that happens to contain literal <, >, or & characters.
    .PARAMETER Markdown
        Raw Markdown text.
    .OUTPUTS
        System.String - an HTML fragment (no <html>/<body> wrapper).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Markdown
    )

    function ConvertTo-SAWMarkdownEncoded {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return '' }
        $Text = $Text -replace '&', '&amp;'
        $Text = $Text -replace '<', '&lt;'
        $Text = $Text -replace '>', '&gt;'
        return $Text
    }

    function ConvertTo-SAWMarkdownInline {
        param([string]$Text)
        $t = ConvertTo-SAWMarkdownEncoded $Text
        $t = [regex]::Replace($t, '\[([^\]]+)\]\(([^)]+)\)', '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
        $t = [regex]::Replace($t, '\*\*([^*]+)\*\*', '<strong>$1</strong>')
        # Runs after **bold** has already consumed every double-asterisk pair, so any
        # remaining single-asterisk pair is genuine *italic* emphasis, not a bold leftover.
        $t = [regex]::Replace($t, '\*([^*]+)\*', '<em>$1</em>')
        $t = [regex]::Replace($t, '`([^`]+)`', '<code>$1</code>')
        return $t
    }

    function ConvertTo-SAWMarkdownTableHtml {
        param([string[]]$Rows)
        $dataRows = @($Rows | Where-Object { $_ -notmatch '^\|?[\s:|-]+\|?$' })
        if ($dataRows.Count -eq 0) { return '' }

        $headerCells = @($dataRows[0] -split '\|' | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() })
        $headHtml = "<tr>$(($headerCells | ForEach-Object { "<th>$(ConvertTo-SAWMarkdownInline $_)</th>" }) -join '')</tr>"

        $bodyHtml = ($dataRows | Select-Object -Skip 1 | ForEach-Object {
            $cells = @($_ -split '\|' | Where-Object { $_ -ne '' } | ForEach-Object { $_.Trim() })
            "<tr>$(($cells | ForEach-Object { "<td>$(ConvertTo-SAWMarkdownInline $_)</td>" }) -join '')</tr>"
        }) -join ''

        return "<table class=""table table-striped table-bordered table-sm""><thead>$headHtml</thead><tbody>$bodyHtml</tbody></table>"
    }

    function Get-SAWMarkdownBlockHtml {
        param([string]$BlockMode, [string[]]$Buffer)
        switch ($BlockMode) {
            'para' { return "<p>$(ConvertTo-SAWMarkdownInline ($Buffer -join ' '))</p>" }
            'ul' { return "<ul>$(($Buffer | ForEach-Object { "<li>$(ConvertTo-SAWMarkdownInline $_)</li>" }) -join '')</ul>" }
            'ol' { return "<ol>$(($Buffer | ForEach-Object { "<li>$(ConvertTo-SAWMarkdownInline $_)</li>" }) -join '')</ol>" }
            'table' { return ConvertTo-SAWMarkdownTableHtml -Rows $Buffer }
        }
        return ''
    }

    $lines = @($Markdown -split "`r?`n")
    $output = @()

    $mode = 'none'
    $buffer = @()

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        $headerMatch = [regex]::Match($trimmed, '^(#{1,6})\s+(.*)$')
        $ulMatch = [regex]::Match($trimmed, '^[-*]\s+(.*)$')
        $olMatch = [regex]::Match($trimmed, '^\d+\.\s+(.*)$')
        $isTableRow = ($trimmed -match '^\|.+\|$')
        $isBlank = ($trimmed -eq '')

        # A soft-wrapped continuation line of the current list item (indented in the source,
        # but not itself a new list marker/header/table row/blank line) - CommonMark treats
        # this as part of the same item, so append to the last buffered item instead of
        # starting a new paragraph, which would otherwise cut the item off mid-sentence.
        if (($mode -eq 'ul' -or $mode -eq 'ol') -and -not $headerMatch.Success -and
            -not $ulMatch.Success -and -not $olMatch.Success -and -not $isTableRow -and
            -not $isBlank -and $buffer.Count -gt 0) {
            $buffer[$buffer.Count - 1] = "$($buffer[$buffer.Count - 1]) $trimmed"
            continue
        }

        $newMode = 'para'
        if ($headerMatch.Success) { $newMode = 'header' }
        elseif ($ulMatch.Success) { $newMode = 'ul' }
        elseif ($olMatch.Success) { $newMode = 'ol' }
        elseif ($isTableRow) { $newMode = 'table' }
        elseif ($isBlank) { $newMode = 'none' }

        if ($newMode -ne $mode -and $mode -ne 'none' -and $buffer.Count -gt 0) {
            $blockHtml = Get-SAWMarkdownBlockHtml -BlockMode $mode -Buffer $buffer
            if ($blockHtml) { $output += $blockHtml }
            $buffer = @()
        }
        $mode = $newMode

        if ($headerMatch.Success) {
            $level = $headerMatch.Groups[1].Value.Length
            $text = $headerMatch.Groups[2].Value
            $output += "<h$level>$(ConvertTo-SAWMarkdownInline $text)</h$level>"
            $mode = 'none'
        }
        elseif ($ulMatch.Success) { $buffer += $ulMatch.Groups[1].Value }
        elseif ($olMatch.Success) { $buffer += $olMatch.Groups[1].Value }
        elseif ($isTableRow) { $buffer += $trimmed }
        elseif (-not $isBlank) { $buffer += $trimmed }
    }

    if ($buffer.Count -gt 0) {
        $blockHtml = Get-SAWMarkdownBlockHtml -BlockMode $mode -Buffer $buffer
        if ($blockHtml) { $output += $blockHtml }
    }

    return ($output -join "`n")
}
