package iobridge

import (
	"io"
	"sync"
)

// Bridge は2つの ReadWriter を双方向にコピーする。
// a→b と b→a を別 goroutine で並走させ、両方が終わるまでブロックする。
// 片方の接続が切れると io.Copy がエラーで戻り、WaitGroup を通じてもう片方も終了する。
func Bridge(a io.ReadWriter, b io.ReadWriter) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(b, a) //nolint:errcheck
	}()
	go func() {
		defer wg.Done()
		io.Copy(a, b) //nolint:errcheck
	}()
	wg.Wait()
}
