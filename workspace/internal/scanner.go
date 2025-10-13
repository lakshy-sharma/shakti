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
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hillu/go-yara/v4"
)

const YaraScanTimeoutSeconds = 60

// This is a persistent object sent to scanners for scanning files.
var yaraRules *yara.Rules

// YaraScanResult holds the matches found for a single file.
type YaraScanResult struct {
	FilePath string          `json:"file_path"`
	Matches  yara.MatchRules `json:"yara_matches"`
	Error    error           `json:"scanning_errors,omitempty"`
}

// This is a one time object which loads the rules and scans the files.
type Scanner struct {
	compiledRules *yara.Rules
	scanResults   []YaraScanResult
	resultsMutex  sync.Mutex
}

// Extracts all rules into designated directory.
func unzipRules(zipPath string, extractionPath string) error {
	logger.Info().Str("zip", zipPath).Str("dest", extractionPath).Msg("starting rule extraction")

	var openedFiles int

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file %s: %w", zipPath, err)
	}
	defer r.Close()

	// Ensure the destination directory exists
	if err := os.MkdirAll(extractionPath, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	for _, f := range r.File {
		// Construct the full path for the extracted file
		fpath := filepath.Join(extractionPath, f.Name)

		// Security check: Prevent Path Traversal (crucial for untrusted zip files)
		relPath, err := filepath.Rel(extractionPath, fpath)
		if err != nil || strings.HasPrefix(relPath, "..") {
			logger.Warn().Str("filename", f.Name).Msg("skipping file due to path traversal risk")
			continue
		}

		// Handle directories
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, f.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", fpath, err)
			}
			continue
		}

		// Handle files
		if err := os.MkdirAll(filepath.Dir(fpath), 0755); err != nil {
			return fmt.Errorf("failed to create file path dir: %w", err)
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return fmt.Errorf("failed to create output file %s: %w", fpath, err)
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return fmt.Errorf("failed to open file in zip: %w", err)
		}

		_, err = io.Copy(outFile, rc)
		// Close handles immediately after use
		rc.Close()
		outFile.Close()
		openedFiles++
		if err != nil {
			return fmt.Errorf("failed to copy content for %s: %w", fpath, err)
		}
	}
	logger.Info().Int("rule_files", openedFiles).Msg("rule extraction complete.")
	return nil
}

// Compiles all yara rules specified inside a target directory.
func compileRules(rulesDir string) (*yara.Rules, error) {
	var rulesAdded int
	var rulesSkipped int

	// Start a new compiler.
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create YARA compiler: %w", err)
	}
	defer compiler.Destroy()

	// Parse all files and
	if err = filepath.WalkDir(rulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// Only process files ending in .yar or .yara
		if strings.HasSuffix(d.Name(), ".yar") || strings.HasSuffix(d.Name(), ".yara") {
			logger.Debug().Str("rule_file", path).Msg("adding rule to compiler")

			// Read the rule content.
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				logger.Error().Err(readErr).Str("rule_file", path).Msg("could not read rule file content")
				rulesSkipped++
				return nil
			}

			// Create a temp compiler for syntax checking
			checkCompiler, checkErr := yara.NewCompiler()
			if checkErr != nil {
				return fmt.Errorf("could not create temporary YARA compiler for checking: %w", checkErr)
			}
			defer checkCompiler.Destroy()
			ruleContent := string(content)

			// Attempt to compile the rule into temp compiler
			if addErr := checkCompiler.AddString(ruleContent, path); addErr != nil {
				logger.Error().Err(addErr).Str("rule_file", path).Msg("syntax error in rule file. skipping")
				rulesSkipped++
				// Do NOT touch the main compiler. Continue walking.
				return nil
			}

			// If temp compiler passed then add rule to main compiler.
			if finalAddErr := compiler.AddString(ruleContent, path); finalAddErr != nil {
				return fmt.Errorf("unexpected error adding pre-checked rule to main compiler %s: %w", path, finalAddErr)
			}

			rulesAdded++
			logger.Debug().Str("rule_file", path).Msg("rule added to compiler")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Get compiled rules from compiler.
	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("could not get compiled rules after adding files: %w", err)
	}

	logger.Info().Int("rule_added", rulesAdded).Int("rules_skipped", rulesSkipped).Msg("compiled rules")
	return rules, nil
}

// Save our scan results into the database.
func saveScanResults(results []YaraScanResult) error {
	if len(results) == 0 {
		logger.Warn().Msg("no scan results to save")
		return nil
	}

	// Ensure database connection is available
	if err := getDBConnection(); err != nil {
		return fmt.Errorf("failed to get database connection: %w", err)
	}
	scanTime := time.Now().Unix()

	// Begin a transaction
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Build the bulk insert query with placeholders
	valueStrings := make([]string, 0, len(results))
	valueArgs := make([]interface{}, 0, len(results)*3)
	skippedCount := 0

	for _, result := range results {
		// Marshal the yara matches to JSON for storage in BLOB
		yaraResultsJSON, err := json.Marshal(result.Matches)
		if err != nil {
			logger.Error().Err(err).Str("filepath", result.FilePath).Msg("failed to marshal yara results, skipping")
			skippedCount++
			continue
		}
		valueStrings = append(valueStrings, "(?, ?, ?)")
		valueArgs = append(valueArgs, scanTime, result.FilePath, yaraResultsJSON)
	}

	// No valid results to upload.
	if len(valueStrings) == 0 {
		logger.Warn().Msg("no valid results to insert after marshaling")
		return nil
	}

	// Construct the full query
	query := fmt.Sprintf(
		"INSERT INTO scan_results (lastscan_time, filepath, yara_results) VALUES %s",
		strings.Join(valueStrings, ","),
	)

	// Execute the bulk insert
	_, err = tx.Exec(query, valueArgs...)
	if err != nil {
		return fmt.Errorf("failed to execute bulk insert: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	logger.Info().
		Int("total_results", len(results)).
		Int("inserted", len(valueStrings)).
		Int("skipped", skippedCount).
		Int64("scan_time", scanTime).
		Msg("scan results saved to database successfully")

	return nil
}

// This entrypoint starts a full scan of target folder.
func startScan() {
	// Start a new scanner object which includes the existing compiled yara rules.
	scanner := Scanner{
		compiledRules: yaraRules,
		scanResults:   []YaraScanResult{},
	}

	// Fetch all files inside the directory and scan them one by one.
	if err := filepath.WalkDir(GlobalConfig.Paths.ScanTargetDirectory, func(path string, d fs.DirEntry, err error) error {
		// Check if path is accessible.
		if err != nil {
			logger.Error().Err(err).Str("path", path).Msg("error accessing path")
			return err
		}

		// If the file is not a directory then scan it using provided rules.
		if !d.IsDir() {
			// Scan the file.
			var matches yara.MatchRules
			err := scanner.compiledRules.ScanFile(path, 0, YaraScanTimeoutSeconds, &matches)

			scanner.resultsMutex.Lock()
			// Store the results.
			scanner.scanResults = append(scanner.scanResults, YaraScanResult{
				FilePath: path,
				Matches:  matches,
				Error:    err,
			})
			scanner.resultsMutex.Unlock()
		}
		return nil
	}); err != nil {
		logger.Error().Err(err).Msg("failed to parse target directory")
	}

	// Save results to a file.
	saveScanResults(scanner.scanResults)
}
