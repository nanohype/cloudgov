package report

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The HTML report is the surface aimed at the reader who will not open the JSON.
// Everything below is an invariant over the template rather than a check of one
// rendering: an edited hex value, a header cell that stops being a button, or a
// theme block that drops a token fails here.

func templateSource(t *testing.T) string {
	t.Helper()
	b, err := templateFS.ReadFile("templates/report.html")
	if err != nil {
		t.Fatalf("read embedded template: %v", err)
	}
	return string(b)
}

// --- WCAG 2.1 contrast -------------------------------------------------------

func channelLuminance(v float64) float64 {
	if v <= 0.04045 {
		return v / 12.92
	}
	return math.Pow((v+0.055)/1.055, 2.4)
}

func relativeLuminance(hex string) (float64, error) {
	h := strings.TrimPrefix(hex, "#")
	if len(h) == 3 {
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	}
	if len(h) != 6 {
		return 0, fmt.Errorf("colour %q is not a hex value", hex)
	}
	var ch [3]float64
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseUint(h[i*2:i*2+2], 16, 8)
		if err != nil {
			return 0, fmt.Errorf("colour %q: %w", hex, err)
		}
		ch[i] = channelLuminance(float64(n) / 255)
	}
	return 0.2126*ch[0] + 0.7152*ch[1] + 0.0722*ch[2], nil
}

func contrastRatio(t *testing.T, fg, bg string) float64 {
	t.Helper()
	lf, err := relativeLuminance(fg)
	if err != nil {
		t.Fatal(err)
	}
	lb, err := relativeLuminance(bg)
	if err != nil {
		t.Fatal(err)
	}
	if lf < lb {
		lf, lb = lb, lf
	}
	return (lf + 0.05) / (lb + 0.05)
}

// The test's own arithmetic is checked against the two reference pairs WCAG
// fixes by definition, so a broken ratio computation cannot pass every colour.
func TestContrastRatioArithmetic(t *testing.T) {
	if got := contrastRatio(t, "#000000", "#ffffff"); math.Abs(got-21) > 0.01 {
		t.Errorf("black on white = %.2f:1, want 21:1", got)
	}
	if got := contrastRatio(t, "#ffffff", "#ffffff"); math.Abs(got-1) > 0.01 {
		t.Errorf("white on white = %.2f:1, want 1:1", got)
	}
}

var (
	tokenRe      = regexp.MustCompile(`--([a-z-]+):\s*(#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?)\b`)
	cssCommentRe = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// stripCSSComments blanks comment bodies, keeping newlines so a later split on
// the dark-scheme marker still lands in the right place.
//
// A token declared inside a comment is not a declaration. Reading one as if it
// were is the fail-open direction for this file: a commented-out `--medium`
// would satisfy the "declared in both themes" check while the live palette had
// none, and the contrast assertion would then measure a colour the page does not
// use. The template's own explanatory comments name tokens, so this is not
// hypothetical.
func stripCSSComments(src string) string {
	return cssCommentRe.ReplaceAllStringFunc(src, func(comment string) string {
		out := make([]byte, 0, len(comment))
		for i := 0; i < len(comment); i++ {
			if comment[i] == '\n' {
				out = append(out, '\n')
				continue
			}
			out = append(out, ' ')
		}
		return string(out)
	})
}

// themeTokens returns the custom properties declared in one CSS block.
func themeTokens(t *testing.T, block string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, m := range tokenRe.FindAllStringSubmatch(stripCSSComments(block), -1) {
		out[m[1]] = m[2]
	}
	return out
}

// The stripper is the load-bearing half of every colour assertion in this file,
// so it carries its own control: a token inside a comment must not be read, a
// live one must be, and line positions must survive.
func TestStripCSSCommentsIgnoresDeclarationsInsideComments(t *testing.T) {
	src := ":root {\n" +
		"  /* --medium: #ffffff was the old value */\n" +
		"  --medium: #8f6000;\n" +
		"}\n"

	tokens := themeTokens(t, src)
	if got := tokens["medium"]; got != "#8f6000" {
		t.Errorf("--medium = %q, want the live declaration #8f6000 rather than the commented one", got)
	}
	if strings.Count(stripCSSComments(src), "\n") != strings.Count(src, "\n") {
		t.Error("stripping comments changed the line count, so block boundaries would shift")
	}
	if commented := themeTokens(t, "/* --ghost: #123456 */"); len(commented) != 0 {
		t.Errorf("a declaration that exists only inside a comment was read: %v", commented)
	}
}

// lightBlock and darkBlock split the template's two :root declarations.
func themeBlocks(t *testing.T) (light, dark map[string]string) {
	t.Helper()
	src := templateSource(t)
	idx := strings.Index(src, "@media (prefers-color-scheme: dark)")
	if idx < 0 {
		t.Fatal("template declares no dark-scheme block; the palette below cannot be theme-aware")
	}
	end := strings.Index(src[idx:], "</style>")
	if end < 0 {
		t.Fatal("dark-scheme block is not inside the <style> element")
	}
	return themeTokens(t, src[:idx]), themeTokens(t, src[idx:idx+end])
}

// Text colours are drawn on --bg and on --card-bg. Checking against whichever of
// the two is nearer the foreground is what makes this a floor rather than a
// best case.
func worstBackground(t *testing.T, theme map[string]string, fg string) (string, float64) {
	t.Helper()
	worstName, worst := "", math.Inf(1)
	for _, bg := range []string{"bg", "card-bg", "table-alt"} {
		v, ok := theme[bg]
		if !ok {
			continue
		}
		if r := contrastRatio(t, fg, v); r < worst {
			worst, worstName = r, bg
		}
	}
	return worstName, worst
}

// severityTokens are rendered as table-cell text at 0.85rem, which is body text
// under WCAG — the 3:1 large-text allowance does not apply.
var severityTokens = []string{"critical", "high", "medium", "low", "info", "green", "red"}

const wcagAABodyText = 4.5

func TestSeverityColoursMeetWCAGAAInBothThemes(t *testing.T) {
	light, darkOverrides := themeBlocks(t)

	// The dark block redefines a subset; anything it omits inherits the light
	// value, which is exactly the failure mode this merge reproduces.
	dark := map[string]string{}
	for k, v := range light {
		dark[k] = v
	}
	for k, v := range darkOverrides {
		dark[k] = v
	}

	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{
		{"light", light},
		{"dark", dark},
	} {
		for _, token := range severityTokens {
			t.Run(theme.name+"/"+token, func(t *testing.T) {
				fg, ok := theme.tokens[token]
				if !ok {
					t.Fatalf("--%s is not defined in the %s theme", token, theme.name)
				}
				bg, ratio := worstBackground(t, theme.tokens, fg)
				if ratio < wcagAABodyText {
					t.Errorf("--%s (%s) on --%s is %.2f:1, below the %.1f:1 WCAG AA floor for body text",
						token, fg, bg, ratio, wcagAABodyText)
				}
			})
		}
	}
}

func TestBodyTextMeetsWCAGAAInBothThemes(t *testing.T) {
	light, darkOverrides := themeBlocks(t)
	dark := map[string]string{}
	for k, v := range light {
		dark[k] = v
	}
	for k, v := range darkOverrides {
		dark[k] = v
	}
	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{
		{"light", light},
		{"dark", dark},
	} {
		t.Run(theme.name, func(t *testing.T) {
			bg, ratio := worstBackground(t, theme.tokens, theme.tokens["fg"])
			if ratio < wcagAABodyText {
				t.Errorf("--fg (%s) on --%s is %.2f:1, below %.1f:1", theme.tokens["fg"], bg, ratio, wcagAABodyText)
			}
		})
	}
}

// --- structure and keyboard access ------------------------------------------

// Sorting is the page's only interactive control. A click handler on a bare <th>
// is unreachable by keyboard and announces nothing, so every header cell has to
// carry a real button.
func TestEveryHeaderCellIsAKeyboardControl(t *testing.T) {
	src := templateSource(t)

	headerCells := regexp.MustCompile(`<th[\s>]`).FindAllString(src, -1)
	if len(headerCells) == 0 {
		t.Fatal("template declares no header cells; this check would pass vacuously")
	}

	buttons := strings.Count(src, `<th scope="col" aria-sort="none"><button type="button">`)
	if buttons != len(headerCells) {
		t.Errorf("%d of %d header cells carry a button with scope and aria-sort", buttons, len(headerCells))
	}
	if strings.Contains(src, "th { ") && strings.Contains(src, "cursor: pointer") &&
		!strings.Contains(src, "th button") {
		t.Error("header cells are styled as clickable without a focusable control inside them")
	}
	if !strings.Contains(src, "th button:focus-visible") {
		t.Error("the sort control declares no focus indicator, so keyboard users cannot see where they are")
	}
}

// A sorted table must not reorder rows across sections. Rows are taken from the
// tbody so a tfoot summary row stays a summary row.
func TestTablesSeparateHeadBodyAndSummaryRows(t *testing.T) {
	src := templateSource(t)

	tables := strings.Count(src, "<table>")
	if tables == 0 {
		t.Fatal("template declares no tables; this check would pass vacuously")
	}
	for _, tag := range []string{"<thead>", "</thead>", "<tbody>", "</tbody>"} {
		if got := strings.Count(src, tag); got != tables {
			t.Errorf("%s appears %d times across %d tables", tag, got, tables)
		}
	}
	if !strings.Contains(src, "<tfoot>") {
		t.Error("the cost table's TOTAL row is not in a tfoot, so sorting drags it into the data")
	}
	if !strings.Contains(src, "tbody.rows") {
		t.Error("the sort routine does not read rows from the tbody, so it can reorder summary rows")
	}
}

// The incomplete record is what separates "found nothing" from "could not look".
// Dropping it here is worse than dropping it from the JSON: this page exists for
// the reader who will not check the JSON.
func TestIncompleteRecordIsRendered(t *testing.T) {
	src := templateSource(t)
	if !strings.Contains(src, "{{if .Incomplete}}") {
		t.Fatal("the template never renders .Incomplete")
	}
	if !strings.Contains(src, "{{range .Incomplete}}") {
		t.Error("the template does not list the individual unread observations")
	}
	cards := strings.Index(src, `<div class="cards">`)
	banner := strings.Index(src, "{{if .Incomplete}}")
	if banner < 0 || cards < 0 || banner > cards {
		t.Error("the incomplete notice renders below the summary counts; it qualifies them, so it goes above")
	}
}
