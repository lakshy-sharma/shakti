package internal

import (
	"database/sql"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

var (
	DB     *sql.DB
	dbFile = filepath.Join(GlobalConfig.Paths.DatabaseDirectory, "shakti.db")
)

// Check if database exists on the system and create one if it does not.
// If DB exists then establish a connection.
func setupDB() {
	// Check if database file exists
	dbExists := false
	if _, err := os.Stat(dbFile); err == nil {
		dbExists = true
		logger.Info().Msg("database already exists")
	}

	// Open or create the database.
	db, err := sql.Open("sqlite3", dbFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to open database")
	}
	defer db.Close()

	// Create tables if DB does not exist.
	if !dbExists {
		createTables()
	}

	// Check DB connection
	if err := db.Ping(); err != nil {
		logger.Fatal().Err(err).Msg("failed to ping database")
	}

	// Load connection
	if err := getDBConnection(); err != nil {
		logger.Error().Err(err).Msg("failed to load database connection")
	}

	logger.Info().Msg("database is ready")
}

func createTables() {
	if err := getDBConnection(); err != nil {
		logger.Fatal().Err(err).Msg("cannot continue")
	}

	// Setup local tables
	createTableSQL := `
	CREATE TABLE IF NOT EXISTS scan_results (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		lastscan_time INTEGER NOT NULL,
		filepath TEXT NOT NULL,
		yara_results BLOB
	);`
	_, err := DB.Exec(createTableSQL)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to create tables in our database")
	}

}

func getDBConnection() error {
	var err error
	DB, err = sql.Open("sqlite3", dbFile)
	if err != nil {
		logger.Error().Err(err).Msg("failed to open database")
		return err
	}
	return nil
}
