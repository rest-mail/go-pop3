package pop3

import (
	"strconv"
	"strings"
	"testing"
)

// These tests pin the RFC 1939 §11 octet-count contract: the size STAT and LIST
// report for a message MUST be the exact number of octets RETR transmits for it,
// measured on the canonical CRLF wire form. RFC 1939 §11 defines that count by
// normalizing the stored end-of-line convention to CRLF ("counts each occurrence
// of this character ... as two octets"); the §3 byte-stuffing of leading-dot
// lines and the CRLF.CRLF terminator are transport framing and are NOT part of
// the message's octet count. [OctetCount] is the single source of truth backends
// use so LIST/STAT and RETR agree.

// mixedRaw exercises every way the stored bytes and the wire octet count can
// diverge from a naive len(): a bare-LF line ending (CRLF normalization adds an
// octet) and a leading-dot line (byte-stuffed on the wire, but counted once in
// the size).
const mixedRaw = "Subject: t\r\n" + // CRLF header (12)
	"\r\n" + // CRLF separator (2)
	"line1\n" + // BARE LF: +1 octet once normalized to CRLF
	".hidden\r\n" + // leading dot: byte-stuffed on the wire, counted once here
	"end\r\n" // (5)

// unstuff reverses RFC 1939 §3 byte-stuffing: a wire line beginning with "."
// carried a prepended termination octet the client strips.
func unstuff(line string) string {
	if strings.HasPrefix(line, ".") {
		return line[1:]
	}
	return line
}

// reconstructWire rebuilds the message octets a client receives from a RETR dot
// body: every line was CRLF-terminated and any leading-dot line was stuffed.
func reconstructWire(body []string) string {
	var b strings.Builder
	for _, l := range body {
		b.WriteString(unstuff(l))
		b.WriteString("\r\n")
	}
	return b.String()
}

// retrOctets sends RETR n and returns the advertised octet count from the
// "+OK <n> octets" status line together with the reconstructed message octets.
func retrOctets(t *testing.T, h *pop3Harness, n int) (advertised int, wire string) {
	t.Helper()
	status := h.cmd("RETR %d", n)
	fields := strings.Fields(status)
	if len(fields) < 2 || fields[0] != "+OK" {
		t.Fatalf("RETR %d status = %q, want \"+OK <n> octets\"", n, status)
	}
	adv, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("RETR %d advertised count %q not an integer: %v", n, fields[1], err)
	}
	return adv, reconstructWire(h.readDotBody())
}

// TestOctetCount_IsCanonicalWireLength pins OctetCount's semantics: it must
// return the CRLF-normalized message length (RFC 1939 §11), NOT the raw stored
// length. For mixedRaw the two differ by the bare LF, so an implementation that
// merely returned len(raw) would fail here.
func TestOctetCount_IsCanonicalWireLength(t *testing.T) {
	got := OctetCount([]byte(mixedRaw))
	want := len(canonicalCRLF(mixedRaw))
	if got != want {
		t.Fatalf("OctetCount = %d, want canonical CRLF length %d", got, want)
	}
	if got == len(mixedRaw) {
		t.Fatalf("OctetCount = %d equals raw len; bare LF was not normalized to CRLF", got)
	}
}

// TestListStatAgreeWithRetr proves that when a backend sizes each message with
// OctetCount (the documented contract), LIST's per-message size, STAT's total,
// and RETR's advertised count all equal the octets RETR actually transmits.
func TestListStatAgreeWithRetr(t *testing.T) {
	const second = "Only headers\r\n" // headers-only, CRLF throughout

	m := newMockBackend()
	m.seed("1", OctetCount([]byte(mixedRaw)), mixedRaw)
	m.seed("2", OctetCount([]byte(second)), second)

	h := newPOP3Harness(t, m)
	h.login()

	// STAT total must equal the sum of the true octet counts.
	stat := h.cmd("STAT")
	wantTotal := OctetCount([]byte(mixedRaw)) + OctetCount([]byte(second))
	if want := "+OK 2 " + strconv.Itoa(wantTotal); stat != want {
		t.Fatalf("STAT = %q, want %q", stat, want)
	}

	// LIST per-message sizes.
	if r := h.cmd("LIST"); !strings.HasPrefix(r, "+OK") {
		t.Fatalf("LIST status = %q", r)
	}
	listSizes := map[int]int{}
	for _, l := range h.readDotBody() {
		f := strings.Fields(l)
		n, _ := strconv.Atoi(f[0])
		sz, _ := strconv.Atoi(f[1])
		listSizes[n] = sz
	}

	// For each message: LIST size == RETR advertised == transmitted message octets.
	for n, raw := range map[int]string{1: mixedRaw, 2: second} {
		adv, wire := retrOctets(t, h, n)
		want := OctetCount([]byte(raw))
		if listSizes[n] != want {
			t.Errorf("msg %d: LIST size = %d, want %d", n, listSizes[n], want)
		}
		if adv != want {
			t.Errorf("msg %d: RETR advertised %d, want %d", n, adv, want)
		}
		if len(wire) != want {
			t.Errorf("msg %d: RETR transmitted %d message octets, want %d (wire=%q)", n, len(wire), want, wire)
		}
		if wire != canonicalCRLF(raw) {
			t.Errorf("msg %d: reconstructed wire %q != canonical form %q", n, wire, canonicalCRLF(raw))
		}
	}
}

// TestNaiveStoredSizeUnderReports characterizes the hazard the tightened
// contract forbids: a backend that reports the raw stored length of bare-LF
// content under-reports relative to what RETR transmits, so LIST/STAT would
// disagree with RETR. OctetCount is the fix — it counts what the wire carries.
func TestNaiveStoredSizeUnderReports(t *testing.T) {
	naive := len(mixedRaw)                  // what a backend using raw len would report
	correct := OctetCount([]byte(mixedRaw)) // what RETR advertises and transmits
	if naive >= correct {
		t.Fatalf("expected raw len %d < canonical octet count %d", naive, correct)
	}

	m := newMockBackend()
	m.seed("1", naive, mixedRaw) // deliberately mis-sized backend
	h := newPOP3Harness(t, m)
	h.login()

	list := h.cmd("LIST 1")
	adv, _ := retrOctets(t, h, 1)
	// The mis-sized backend makes LIST disagree with RETR; sizing via OctetCount
	// (as the contract now requires) is what makes them agree.
	if got := "+OK 1 " + strconv.Itoa(naive); list != got {
		t.Fatalf("LIST 1 = %q, want %q", list, got)
	}
	if adv == naive {
		t.Fatalf("RETR advertised the naive size %d; expected the canonical %d", naive, correct)
	}
}
