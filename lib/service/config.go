package service

type Config struct {
	DatabaseUri           string `envconfig:"DATABASE_URI" required:"true"`
	SentryDSN             string `envconfig:"SENTRY_DSN"`
	LogFilePath           string `envconfig:"LOG_FILE_PATH"`
	JWTSecret             []byte `envconfig:"JWT_SECRET" required:"true"`
	JWTRefreshTokenExpiry int    `envconfig:"JWT_REFRESH_EXPIRY" default:"604800"` // in seconds, default 7 days
	JWTAccessTokenExpiry  int    `envconfig:"JWT_ACCESS_EXPIRY" default:"172800"`  // in seconds, default 2 days
	LNDAddress            string `envconfig:"LND_ADDRESS" required:"true"`
	LNDMacaroonFile       string `envconfig:"LND_MACAROON_FILE"`
	LNDCertFile           string `envconfig:"LND_CERT_FILE"`
	LNDMacaroonHex        string `envconfig:"LND_MACAROON_HEX"`
	LNDCertHex            string `envconfig:"LND_CERT_HEX"`
	CustomName            string `envconfig:"CUSTOM_NAME"`
	Host                  string `envconfig:"HOST" default:"localhost:3000"`
	Port                  int    `envconfig:"PORT" default:"3000"`
	DefaultRateLimit      int    `envconfig:"DEFAULT_RATE_LIMIT" default:"10"`
	StrictRateLimit       int    `envconfig:"STRICT_RATE_LIMIT" default:"10"`
	BurstRateLimit        int    `envconfig:"BURST_RATE_LIMIT" default:"1"`
	EnablePrometheus      bool   `envconfig:"ENABLE_PROMETHEUS" default:"false"`
	PrometheusPort        int    `envconfig:"PROMETHEUS_PORT" default:"9092"`
	WebhookUrl            string `envconfig:"WEBHOOK_URL"`
	FeeReserve            bool   `envconfig:"FEE_RESERVE" default:"false"`
	AllowAccountCreation  bool   `envconfig:"ALLOW_ACCOUNT_CREATION" default:"true"`
	MaxReceiveAmount      int64  `envconfig:"MAX_RECEIVE_AMOUNT" default:"0"`
	MaxSendAmount         int64  `envconfig:"MAX_SEND_AMOUNT" default:"0"`
	MaxAccountBalance     int64  `envconfig:"MAX_ACCOUNT_BALANCE" default:"0"`
}
