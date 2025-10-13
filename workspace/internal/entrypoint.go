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
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

// This is the main function which parses complete config and starts relevant activities
func Entrypoint(config_path string) {
	var err error

	// Parse the configuration file and load it.
	GlobalConfig, err = loadConfig(config_path)
	if err != nil {
		log.Error().Msg("failed to load configuration")
	}

	// Setup logging.
	logger = getLogger(GlobalConfig)

	// Setup temp directory for working.
	if err := os.MkdirAll(GlobalConfig.TempDirectory, 0755); err != nil {
		logger.Error().Err(err).Msg("failed to setup work directory. change your temp directory")
		return
	}

	if err := os.MkdirAll(GlobalConfig.OutputDirectory, 0755); err != nil {
		logger.Error().Err(err).Msg("failed to setup output directory. change your output directory")
		return
	}
	// Extract and Load the yara rules.
	rulesDir := filepath.Join(GlobalConfig.TempDirectory, GlobalConfig.FilescannerRules.RulesExtractDir)
	if err := unzipRules(GlobalConfig.FilescannerRules.RulesZipPath, rulesDir); err != nil {
		logger.Error().Err(err).Msg("failed to extract scanner rules")
		return
	}
	yaraRules, err = compileRules(rulesDir)
	if err != nil {
		logger.Error().Err(err).Msg("failed to load scanner rules")
		return
	}

	// Start the code into designated mode.
	logger.Info().Str("operation_mode", GlobalConfig.OperationMode).Str("target_directory", GlobalConfig.TargetDirectory).Msg("locked and loaded ready to go!")

	switch GlobalConfig.OperationMode {
	case "instant_scan":
		startScan()
	case "daemon_mode":
		startDaemon()
	}
}
