// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upload

/*
func TestMaxParallelUploadOpsReached(t *testing.T) {
	_ = testlog.SetLogger(t)
	opLimit := 4

	u := New(500, opLimit, 0)

	var err error
	for i := 0; i < opLimit; i++ {
		_, err = u.Begin(100, "", "")
		assert.NoError(t, err)
	}

	_, err = u.Begin(100, "", "")
	assert.ErrorIs(t, err, ErrMaxConcurrentUploads)
}

func TestMaxParallelUploadOpsReleased(t *testing.T) {
	opLimit := 4
	u := New(500, opLimit, 0)

	// generate max operations
	ops := make([]Info, 0, opLimit)
	for i := 0; i < opLimit; i++ {
		op, err := u.Begin(100, strconv.Itoa(i), "")
		require.NoError(t, err)
		ops = append(ops, op)
	}
	// and verify max was reached
	_, err := u.Begin(100, "X", "")
	assert.ErrorIs(t, err, ErrMaxConcurrentUploads)

	// finishing an op should release the hold and allow another to begin
	_, err = u.Complete(ops[0].ID)
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond) // occasionally, a little time was required for the change to propagate

	_, err = u.Begin(100, "Y", "")
	assert.NoError(t, err)
}

func TestMaxParallelChunks(t *testing.T) {
	chunkLim := 3

	u := New(104857600, 1, chunkLim)

	// start an operation, that can have more than the test limit chunks
	op, err := u.Begin(MaxChunkSize*int64(chunkLim+2), "", "")
	require.NoError(t, err)

	// upload up to the limit chunks, without releasing the request
	for i := 0; i < chunkLim; i++ {
		_, err := u.Chunk(op.ID, i)
		require.NoError(t, err)
	}

	_, err = u.Chunk(op.ID, chunkLim)
	assert.ErrorIs(t, err, ErrMaxConcurrentUploads)
}

func TestMaxParallelChunksReleased(t *testing.T) {
	chunkLim := 3

	u := New(104857600, 1, chunkLim)

	// start an operation, that can have more than the test limit chunks
	op, err := u.Begin(MaxChunkSize*int64(chunkLim+2), "", "")
	require.NoError(t, err)

	// upload up to the limit chunks, without releasing the request
	chunks := make([]ChunkInfo, 0, chunkLim)
	for i := 0; i < chunkLim; i++ {
		info, err := u.Chunk(op.ID, i)
		require.NoError(t, err)
		chunks = append(chunks, info)
	}
	_, err = u.Chunk(op.ID, chunkLim)
	assert.ErrorIs(t, err, ErrMaxConcurrentUploads)

	chunks[0].Token.Release()

	_, err = u.Chunk(op.ID, chunkLim)
	assert.NoError(t, err)
}

func TestUploadChunkCount(t *testing.T) {
	tests := []struct {
		FileSize      int64
		ExpectedCount int
		Name          string
	}{
		{10, 1, "Tiny files take 1 chunk"},
		{MaxChunkSize, 1, "Precisely 1 chunk size bytes will fit in 1 chunk"},
		{MaxChunkSize + 1, 2, "ChunkSize+1 bytes takes 2 chunks"},
		{MaxChunkSize * 2.5, 3, "2.5x chunk size fits in 3 chunks"},
		{7534559605, 1797, "7.5Gb file"},
	}

	u := New(8388608000, len(tests), 1)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			info, err := u.Begin(tc.FileSize, "", "")
			assert.NoError(t, err)
			assert.Equal(t, tc.ExpectedCount, info.Count)
		})
	}
}

func TestChunkMarksFinal(t *testing.T) {
	tests := []struct {
		FileSize   int64
		FinalChunk int
		Name       string
	}{
		{10, 0, "Small file only chunk is final"},
		{MaxChunkSize, 0, "1 chunksize only chunk is final"},
		{MaxChunkSize + 1, 1, "ChunkSize+1 bytes takes 2 chunks"},
		{MaxChunkSize * 2.5, 2, "2.5x chunk size"},
		{7534559605, 1796, "7.5Gb file"},
	}

	u := New(8388608000, len(tests), 4)

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			info, err := u.Begin(tc.FileSize, "", "")
			assert.NoError(t, err)

			if tc.FinalChunk > 0 {
				prev, err := u.Chunk(info.ID, tc.FinalChunk-1)
				assert.NoError(t, err)
				assert.Falsef(t, prev.Final, "previous chunk ID before last should not be marked final")
				prev.Token.Release()
			}

			chunk, err := u.Chunk(info.ID, tc.FinalChunk)
			assert.NoError(t, err)
			assert.True(t, chunk.Final)
			chunk.Token.Release()
		})
	}
}

func TestMaxFileSize(t *testing.T) {
	tests := []struct {
		MaxSize     int64
		TryFile     int64
		ShouldError bool
		Name        string
	}{
		{500, 800, true, "800 is too large"},
		{800, 500, false, "file within limits"},
		{1024, 1023, false, "1-less than limit"},
		{1024, 1024, false, "file is exactly limit"},
		{1024, 1025, true, "file is 1 over limit"},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			u := New(tc.MaxSize, 1, 1)
			_, err := u.Begin(tc.TryFile, "", "")
			if tc.ShouldError {
				assert.ErrorIs(t, err, ErrFileSizeTooLarge)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
*/
