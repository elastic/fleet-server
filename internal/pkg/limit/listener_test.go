package limit

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/nettest"

	testlog "github.com/elastic/fleet-server/v7/internal/pkg/testing/log"
)

func TestLimitListener(t *testing.T) {
	logger := testlog.SetLogger(t)
	ll, err := nettest.NewLocalListener("tcp")
	require.NoError(t, err)
	defer ll.Close()
	l := Listener(ll, 1, &logger)

	ch := make(chan struct{})
	done := make(chan struct{})

	t.Log("Form 1st connection")
	go func() {
		_, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)
	}()
	// should accept a connection
	conn, err := l.Accept()
	require.NoError(t, err, "expected to be able to form one connection")

	t.Log("Form 2nd connection")
	go func() {
		conn, err := net.Dial("tcp", l.Addr().String())
		require.NoError(t, err)

		select {
		case <-ch:
		case <-time.After(time.Second):
			require.Fail(t, "expected channel write before timeout")
		}

		var p []byte
		n, err := conn.Read(p)
		assert.NoError(t, err)
		assert.Equal(t, 0, n)

		err = conn.Close()
		require.NoError(t, err)
		done <- struct{}{}
	}()

	conn2, err := l.Accept()
	require.NoError(t, err)
	n, err := conn2.Write([]byte(`hellow world`))
	ch <- struct{}{}
	assert.Error(t, err)
	assert.Equal(t, 0, n)

	err = conn.Close()
	require.NoError(t, err)
	err = l.Close()
	require.NoError(t, err)
	<-done
}
