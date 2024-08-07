package config

type PostgresConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	DBName   string
}

type BackendDSConfig struct {
	Host                  string
	MetricsExport         bool
	GpuMetricsExport      bool
	MetricsExportInterval int // in seconds

	ReqBufferSize        int
	ConnBufferSize       int
	KafkaEventBufferSize int
}
