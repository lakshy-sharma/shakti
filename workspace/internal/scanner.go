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
		if !strings.HasPrefix(fpath, filepath.Clean(extractionPath)+string(os.PathSeparator)) {
			logger.Warn().Str("filename", f.Name).Msg("Skipping file due to path traversal risk")
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

		if err != nil {
			return fmt.Errorf("failed to copy content for %s: %w", fpath, err)
		}
	}
	logger.Info().Msg("rule extraction complete.")
	return nil
}

// Compiles all yara rules specified inside a target directory.
func compileRules(rulesDir string) (*yara.Rules, error) {
	// Start a new compiler.
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("could not create YARA compiler: %w", err)
	}
	var rulesAdded int
	var rulesSkipped int

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

			content, readErr := os.ReadFile(path)
			if readErr != nil {
				logger.Error().Err(readErr).Str("rule_file", path).Msg("could not read rule file content")
				rulesSkipped++
				return nil // Continue walking
			}

			// 2. Create a temporary compiler for syntax checking (the "dummy compiler")
			checkCompiler, checkErr := yara.NewCompiler()
			if checkErr != nil {
				// This is a critical error, stop the process
				return fmt.Errorf("could not create temporary YARA compiler for checking: %w", checkErr)
			}

			ruleContent := string(content)

			// 3. Attempt to compile the rule using the temporary compiler.
			// This check will poison the temporary compiler if the syntax is bad.
			if addErr := checkCompiler.AddString(ruleContent, path); addErr != nil {
				logger.Error().Err(addErr).Str("rule_file", path).Msg("syntax error in rule file. skipping")
				rulesSkipped++
				// Do NOT touch the main compiler. Continue walking.
				return nil
			}

			// 4. If the temporary check passed, add the rules to the main compiler.
			if finalAddErr := compiler.AddString(ruleContent, path); finalAddErr != nil {
				// This indicates a more serious issue (e.g., memory exhaustion, internal YARA error)
				return fmt.Errorf("unexpected error adding pre-checked rule to main compiler %s: %w", path, finalAddErr)
			}

			rulesAdded++
			logger.Debug().Str("rule_file", path).Msg("rule added to compiler")
		}
		return nil
	}); err != nil {
		return nil, err
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("could not get compiled rules after adding files: %w", err)
	}

	return rules, nil
}

// saveScanResults writes the collected results to a structured JSON file.
func saveScanResults(results []YaraScanResult) error {
	if len(results) == 0 {
		logger.Warn().Msg("no scan results to save")
		return nil
	}

	// Generate a unique filename based on the current time
	timestamp := time.Now().Format("20060102_150405")
	outputFile := filepath.Join(GlobalConfig.OutputDirectory, fmt.Sprintf("results_%s.json", timestamp))

	// Marshals the results struct into pretty-printed JSON
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal scan results to JSON: %w", err)
	}

	// Write the JSON data to a file
	if err := os.WriteFile(outputFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write results file %s: %w", outputFile, err)
	}

	logger.Info().Str("filename", outputFile).Msg("scan results saved successfully")
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
	filepath.WalkDir(GlobalConfig.TargetDirectory, func(path string, d fs.DirEntry, err error) error {
		// Check if path is accessible.
		if err != nil {
			logger.Error().Err(err).Str("path", path).Msg("error accessing path")
			return err
		}

		// If the file is not a directory then scan it using provided rules.
		if !d.IsDir() {
			// Scan the file.
			var matches yara.MatchRules
			err := yaraRules.ScanFile(path, 0, 60, &matches)

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
	})

	// Save results to a file.
	saveScanResults(scanner.scanResults)
}
