package shadowtls

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
)

func TestVerifiedConnWriteVectorisedPreservesPayloadAndState(t *testing.T) {
	t.Parallel()

	sender, receiver, wire := newTestVerifiedConnPair(t)

	writeDone := make(chan error, 1)
	go func() {
		err := sender.WriteVectorised([]*buf.Buffer{
			buf.As([]byte("vectorised ")),
			buf.As([]byte("payload")),
		})
		if err == nil {
			_, err = sender.Write([]byte(" followed by a regular write"))
		}
		writeDone <- err
	}()

	want := []byte("vectorised payload followed by a regular write")
	got := make([]byte, len(want))
	_, err := io.ReadFull(receiver, got)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload mismatch:\n got: %q\nwant: %q", got, want)
	}
	assertValidApplicationDataRecords(t, wire.Bytes(), want)
}

func TestVerifiedConnWriteVectorisedSplitsLargePayload(t *testing.T) {
	t.Parallel()

	sender, receiver, wire := newTestVerifiedConnPair(t)

	bufferSizes := []int{
		0, 1, 16384, 16385, 65531, 65532,
		65535, 65535, 65535, 65535, 65535, 65535,
	}
	totalSize := 0
	for _, size := range bufferSizes {
		totalSize += size
	}
	if totalSize <= 512000 {
		t.Fatalf("test payload must exceed the vectorised copy threshold: %d", totalSize)
	}
	want := make([]byte, totalSize)
	for index := range want {
		want[index] = byte((index*31 + 7) % 251)
	}
	buffers := make([]*buf.Buffer, 0, len(bufferSizes))
	offset := 0
	for _, size := range bufferSizes {
		bufferCapacity := size
		if bufferCapacity == 0 {
			bufferCapacity = 1
		}
		buffer := buf.NewSize(bufferCapacity)
		if _, err := buffer.Write(want[offset : offset+size]); err != nil {
			t.Fatal(err)
		}
		buffers = append(buffers, buffer)
		offset += size
	}

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- sender.WriteVectorised(buffers)
	}()

	got := make([]byte, len(want))
	_, err := io.ReadFull(receiver, got)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if err = <-writeDone; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("payload mismatch")
	}
	for index, buffer := range buffers {
		if buffer.Cap() != 0 {
			t.Fatalf("buffer %d was not released", index)
		}
	}
	assertValidApplicationDataRecords(t, wire.Bytes(), want)
}

func assertValidApplicationDataRecords(t *testing.T, wire []byte, want []byte) {
	t.Helper()

	hmacState := newTestHMAC()
	payload := make([]byte, 0, len(want))
	recordCount := 0
	for len(wire) > 0 {
		if len(wire) < tlsHeaderSize {
			t.Fatalf("truncated TLS header: %d bytes", len(wire))
		}
		if wire[0] != applicationData || wire[1] != 3 || wire[2] != 3 {
			t.Fatalf("unexpected TLS record header: %x", wire[:tlsHeaderSize])
		}
		recordLength := int(binary.BigEndian.Uint16(wire[3:tlsHeaderSize]))
		if recordLength > hmacSize+16384 {
			t.Fatalf("TLS application data record is too large: %d", recordLength)
		}
		fullLength := tlsHeaderSize + recordLength
		if len(wire) < fullLength {
			t.Fatalf("truncated TLS record: have %d bytes, want %d", len(wire), fullLength)
		}
		recordHMAC := wire[tlsHeaderSize:tlsHmacHeaderSize]
		recordPayload := wire[tlsHmacHeaderSize:fullLength]
		hmacState.Write(recordPayload)
		wantHMAC := hmacState.Sum(nil)[:hmacSize]
		if !hmac.Equal(recordHMAC, wantHMAC) {
			t.Fatalf("record %d HMAC mismatch: got %x, want %x", recordCount, recordHMAC, wantHMAC)
		}
		hmacState.Write(wantHMAC)
		payload = append(payload, recordPayload...)
		wire = wire[fullLength:]
		recordCount++
	}
	if !bytes.Equal(payload, want) {
		t.Fatal("wire payload mismatch")
	}
	if len(want) > 16384 && recordCount < 2 {
		t.Fatalf("payload was not split: %d record", recordCount)
	}
}

func newTestVerifiedConnPair(t *testing.T) (*verifiedConn, *verifiedConn, *recordingConn) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	acceptDone := make(chan struct {
		conn net.Conn
		err  error
	}, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		acceptDone <- struct {
			conn net.Conn
			err  error
		}{conn, acceptErr}
	}()
	left, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	accepted := <-acceptDone
	listener.Close()
	if accepted.err != nil {
		left.Close()
		t.Fatal(accepted.err)
	}
	right := accepted.conn
	deadline := time.Now().Add(5 * time.Second)
	if err := left.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := right.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		left.Close()
		right.Close()
	})

	recordingLeft := &recordingConn{Conn: left}
	return newVerifiedConn(recordingLeft, newTestHMAC(), newTestHMAC(), nil),
		newVerifiedConn(right, newTestHMAC(), newTestHMAC(), nil), recordingLeft
}

func newTestHMAC() hash.Hash {
	hmacHash := hmac.New(sha1.New, []byte("test password"))
	hmacHash.Write([]byte("test server random"))
	hmacHash.Write([]byte("S"))
	return hmacHash
}

type recordingConn struct {
	net.Conn
	access sync.Mutex
	writes bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.access.Lock()
	c.writes.Write(p[:n])
	c.access.Unlock()
	return n, err
}

func (c *recordingConn) Bytes() []byte {
	c.access.Lock()
	defer c.access.Unlock()
	return bytes.Clone(c.writes.Bytes())
}
