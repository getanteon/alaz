package datastore

import (
	"alaz/config"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"time"

	_ "github.com/lib/pq"

	"alaz/log"
)

const podTableName = "pod"
const serviceTableName = "service"
const requestTableName = "request"

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
	nConn, err := strconv.Atoi(os.Getenv("POSTGRES_MAX_OPEN_CONN"))
	if err != nil {
		nConn = 30
	}
	db.SetMaxOpenConns(nConn)

	return db, nil
}

type Repository struct {
	db    *sql.DB
	stmts map[string]*sql.Stmt
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

	r := Repository{db, make(map[string]*sql.Stmt)}
	r.prepareStatements()

	return r
}

func (r Repository) prepareStatements() {
	r.stmts["create_pod"] = r.prepareCreatePodStatement()
	r.stmts["update_pod"] = r.prepareUpdatePodStatement()
	r.stmts["delete_pod"] = r.prepareDeletePodStatement()
	r.stmts["create_service"] = r.prepareCreateServiceStatement()
	r.stmts["update_service"] = r.prepareUpdateServiceStatement()
	r.stmts["delete_service"] = r.prepareDeleteServiceStatement()
	r.stmts["create_request"] = r.prepareCreateRequestStatement()
}

func (r Repository) prepareCreatePodStatement() *sql.Stmt {
	query := fmt.Sprintf("INSERT INTO %s (uid,name,namespace,image,ip) VALUES($1, $2,$3,$4,$5)", podTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing create-pod query")
		return nil
	}
	return stmt
}

func (r Repository) prepareUpdatePodStatement() *sql.Stmt {
	query := fmt.Sprintf("UPDATE %s SET name = $1, namespace = $2 , image = $3 , ip = $4 WHERE uid = $5", podTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing update-pod query")
		return nil
	}
	return stmt
}

func (r Repository) prepareDeletePodStatement() *sql.Stmt {
	query := fmt.Sprintf("UPDATE %s SET deleted = true WHERE uid = $1", podTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing delete-pod query")
		return nil
	}
	return stmt
}

func (r Repository) prepareCreateServiceStatement() *sql.Stmt {
	query := fmt.Sprintf("INSERT INTO %s (uid,name,namespace,type,cluster_ip) VALUES($1, $2,$3,$4,$5)", serviceTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing create-service query")
		return nil
	}
	return stmt
}

func (r Repository) prepareUpdateServiceStatement() *sql.Stmt {
	query := fmt.Sprintf("UPDATE %s SET name = $1, namespace = $2 , type = $3,  cluster_ip = $4 WHERE uid = $5", serviceTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing update-service query")
		return nil
	}
	return stmt
}

func (r Repository) prepareDeleteServiceStatement() *sql.Stmt {
	query := fmt.Sprintf("UPDATE %s SET deleted = true WHERE uid = $1", serviceTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing delete-service query")
		return nil
	}
	return stmt
}

func (r Repository) prepareCreateRequestStatement() *sql.Stmt {
	query := fmt.Sprintf("INSERT INTO %s (start_time,latency,from_ip,from_type,from_uid,to_ip,to_type,to_uid,protocol,completed,status_code,fail_reason,method,path) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", requestTableName)
	stmt, err := r.db.Prepare(query)
	if err != nil {
		log.Logger.Error().Err(err).Msg("error preparing create-request query")
		return nil
	}
	return stmt
}

func (r Repository) Close() {

	for _, stmt := range r.stmts {
		stmt.Close()
	}

	r.db.Close()

}

func (r Repository) CreatePod(dto Pod) error {
	stmt := r.stmts["create_pod"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRowContext(ctx, dto.UID, dto.Name, dto.Namespace, dto.Image, dto.IP)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}

func (r Repository) UpdatePod(dto Pod) error {
	stmt := r.stmts["update_pod"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRowContext(ctx, dto.Name, dto.Namespace, dto.Image, dto.IP, dto.UID)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}

func (r Repository) DeletePod(dto Pod) error {
	stmt := r.stmts["delete_pod"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRowContext(ctx, dto.UID)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}

func (r Repository) CreateService(dto Service) error {
	stmt := r.stmts["create_service"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRow(ctx, dto.UID, dto.Name, dto.Namespace, dto.Type, dto.ClusterIP)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}

func (r Repository) UpdateService(dto Service) error {
	stmt := r.stmts["update_service"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRow(ctx, dto.Name, dto.Namespace, dto.Type, dto.ClusterIP, dto.UID)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}

func (r Repository) DeleteService(dto Service) error {
	stmt := r.stmts["delete_service"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRow(ctx, dto.UID)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}

func (r Repository) PersistRequest(dto Request) error {
	stmt := r.stmts["create_request"]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	row := stmt.QueryRowContext(ctx, dto.StartTime.UnixMilli(), dto.Latency, dto.FromIP, dto.FromType, dto.FromUID, dto.ToIP, dto.ToType, dto.ToUID, dto.Protocol, dto.Completed, dto.StatusCode, dto.FailReason, dto.Method, dto.Path)
	if row.Err() != nil {
		log.Logger.Error().Err(row.Err()).Msg("Could not execute prepared statement")
		return fmt.Errorf("could not execute prepared statement")
	}
	return nil
}
