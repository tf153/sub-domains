package discover

import (
	"bufio"
	"context"
	"os"
	"strings"
	"sync"

	"github.com/rahuljoshi/subscope/internal/dnsx"
	"github.com/rahuljoshi/subscope/internal/model"
)

// Brute attempts to resolve domain prefixed by each word in the wordlist.
// Any candidate that resolves (A/AAAA/CNAME) is added to out.
//
// wordlistPath may be empty, in which case the built-in default list is used.
func Brute(ctx context.Context, domain, wordlistPath string, resolver *dnsx.Resolver, concurrency int, out *model.Set) error {
	words, err := loadWordlist(wordlistPath)
	if err != nil {
		return err
	}

	if concurrency <= 0 {
		concurrency = 50
	}

	jobs := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for word := range jobs {
				host := word + "." + domain
				if resolver.Exists(ctx, host) {
					out.Add(host, "brute")
				}
			}
		}()
	}

	for _, w := range words {
		select {
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return ctx.Err()
		case jobs <- w:
		}
	}
	close(jobs)
	wg.Wait()
	return nil
}

func loadWordlist(path string) ([]string, error) {
	if path == "" {
		return defaultWordlist, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	seen := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		w := strings.ToLower(strings.TrimSpace(sc.Text()))
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		if _, ok := seen[w]; ok {
			continue
		}
		seen[w] = struct{}{}
		words = append(words, w)
	}
	return words, sc.Err()
}
