package datastore

import (
	"alaz/config"
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"

	"alaz/log"
)

const podTableName = "pod"
const serviceTableName = "service"

func connectToPostgresDb(psqlconn string) (*sql.DB, error) {
	// open database
	db, err := sql.Open("postgres", psqlconn)
	if err != nil {
		return nil, err
	}

	// check db
	err = db.Ping()
	if err != nil {
		return nil, err
	}

	db.SetMaxIdleConns(10)
	// db.SetConnMaxLifetime(30 * time.Second)
	db.SetMaxOpenConns(500) // stage db 1000

	return db, nil
}

type Repository struct {
	db *sql.DB
}

func NewRepository(appConfig config.PostgresConfig) Repository {
	// connection string
	psqlconn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		appConfig.Host, appConfig.Port, appConfig.Username, appConfig.Password, appConfig.DBName)

	db, err := connectToPostgresDb(psqlconn)
	if err != nil {
		log.Logger.Fatal().Err(err).Msg("failed to connect to postgres db")
	}
	fmt.Println("Connected!")

	return Repository{db}
}

func (r Repository) Close() {
	r.db.Close()
}

func (r Repository) CreatePod(dto Pod) error {
	query := fmt.Sprintf("INSERT INTO %s (uid,name,namespace,image,ip) VALUES($1, $2,$3,$4,$5)", podTableName)
	stmt, err := r.db.Prepare(query)
	defer stmt.Close()
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing query")
		return fmt.Errorf("error preparing query")
	}

	row := stmt.QueryRow(dto.UID, dto.Name, dto.Namespace, dto.Image, dto.IP)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("Could not execute prepared statement")
	}
	return nil
}

func (r Repository) CreateService(dto Service) error {
	query := fmt.Sprintf("INSERT INTO %s (uid,name,namespace,type,cluster_ip) VALUES($1, $2,$3,$4,$5)", serviceTableName)
	stmt, err := r.db.Prepare(query)
	defer stmt.Close()
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing query")
		return fmt.Errorf("error preparing query")
	}

	row := stmt.QueryRow(dto.UID, dto.Name, dto.Namespace, dto.Type, dto.ClusterIP)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("Could not execute prepared statement")
	}
	return nil
}
