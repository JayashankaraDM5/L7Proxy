package proxy

import (
	"log"
	"time"

	"github.com/fsnotify/fsnotify"
)

// StartFileWatcher watches the specified file path for changes
// and closes all managed connections on modification events.
func StartFileWatcher(filePath string, cm *ConnManager) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("Failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	err = watcher.Add(filePath)
	if err != nil {
		log.Fatalf("Failed to watch file %s: %v", filePath, err)
	}

	log.Printf("Started watcher on file: %s", filePath)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			log.Printf("File event detected: %s Op: %s", event.Name, event.Op)

			// On Write or Create operations close all connections gracefully
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				log.Printf("Triggering graceful close of all connections due to file change")
				cm.CloseByFilter(func(meta *ConnMeta) bool {
					return true // close all connections unconditionally
				})
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)

		case <-time.After(24 * time.Hour):
			// Prevent blocking forever; can be adjusted or removed as needed
		}
	}
}

