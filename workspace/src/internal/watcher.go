/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU Affero General Public License as
	published by the Free Software Foundation, either version 3 of the
	License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU Affero General Public License for more details.

	You should have received a copy of the GNU Affero General Public License
	along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package internal

import (
	"github.com/fsnotify/fsnotify"
)

// StartDaemon is called when the application needs to be run continously in background.
// It can monitor the filesystem for any changes and scan new incoming documents for any threats.
func startDaemon() {
	// Create a new filesystem watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to setup watcher")
	}
	defer watcher.Close()

	// Add target to watch for any new changes.
	err = watcher.Add(GlobalConfig.ScanSettings.TargetDirectory)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to add scan target into watcher")
	}
	logger.Info().Str("directory", GlobalConfig.ScanSettings.TargetDirectory).Msg("watcher setup for scan target")

	// Start an infinite loop to watch events and scan files as they change.
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			logger.Info().Str("event", event.String()).Msg("received event")

			if event.Has(fsnotify.Write) {
				logger.Info().Str("filename", event.Name).Str("operation", event.Op.String()).Msg("scanning modified file")
			} else if event.Has(fsnotify.Create) {
				logger.Info().Str("filename", event.Name).Str("operation", event.Op.String()).Msg("scanning created file")
			} else if event.Has(fsnotify.Chmod) {
				logger.Info().Str("filename", event.Name).Str("operation", event.Op.String()).Msg("file changed its mode")
			}

			// TODO
			// Handle other changes (Rename, Remove, Chmod) as you like.
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			logger.Error().Err(err).Msg("filesystem watcher is facing some errors")
		}
	}
}
