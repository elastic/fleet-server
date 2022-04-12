package limit

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/time/rate"
)

func TestWrite(t *testing.T) {
	req := httptest.NewRequest("GET", "https://example.com", nil)
	handler := func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, "Hello, World!")
		if err != nil {
			w.WriteHeader(500)
		}
	}

	t.Run("no limit", func(t *testing.T) {
		w := httptest.NewRecorder()
		wr := WrapResponseWriter(context.Background(), w, nil)
		handler(wr, req)
		resp := w.Result()
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(body))
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("large limit", func(t *testing.T) {
		w := httptest.NewRecorder()
		l := rate.NewLimiter(rate.Limit(100), 100)
		wr := WrapResponseWriter(context.Background(), w, l)
		handler(wr, req)
		resp := w.Result()
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(body))
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("small limit", func(t *testing.T) {
		w := httptest.NewRecorder()
		l := rate.NewLimiter(rate.Limit(5), 5)
		wr := WrapResponseWriter(context.Background(), w, l)
		handler(wr, req)
		resp := w.Result()
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "Hello, World!", string(body))
		assert.Equal(t, 200, resp.StatusCode)
	})

	t.Run("limit context cancelled", func(t *testing.T) {
		w := httptest.NewRecorder()
		l := rate.NewLimiter(rate.Limit(100), 100)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		wr := WrapResponseWriter(ctx, w, l)
		handler(wr, req)
		resp := w.Result()
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		assert.Equal(t, "", string(body))
		assert.Equal(t, 500, resp.StatusCode)
	})
}
