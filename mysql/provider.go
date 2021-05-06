package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/hashicorp/go-version"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/Azure/go-autorest/autorest/azure/auth"

	"golang.org/x/net/proxy"
)

const (
	cleartextPasswords = "cleartext"
	nativePasswords    = "native"
	aadAuthentication  = "aad_auth"
)

type MySQLConfiguration struct {
	Config              *mysql.Config
	MaxConnLifetime     time.Duration
	MaxOpenConns        int
	ConnectRetryTimeout time.Duration
	db                  *sql.DB
}

func (c *MySQLConfiguration) GetDbConn() (*sql.DB, error) {
	if c.db == nil {
		db, err := connectToMySQL(c)
		if err != nil {
			return nil, err
		}
		c.db = db
	}
	return c.db, nil
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_ENDPOINT", nil),
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if value == "" {
						errors = append(errors, fmt.Errorf("endpoint must not be an empty string"))
					}

					return
				},
			},

			"username": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_USERNAME", nil),
			},

			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_PASSWORD", nil),
			},

			"proxy": {
				Type:     schema.TypeString,
				Optional: true,
				DefaultFunc: schema.MultiEnvDefaultFunc([]string{
					"ALL_PROXY",
					"all_proxy",
				}, nil),
				ValidateFunc: validation.StringMatch(regexp.MustCompile(`^socks5h?://.*:\d+$`), "The proxy URL is not a valid socks url."),
			},

			"tls": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("MYSQL_TLS_CONFIG", "false"),
				ValidateFunc: validation.StringInSlice([]string{
					"true",
					"false",
					"skip-verify",
				}, false),
			},

			"max_conn_lifetime_sec": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			"max_open_conns": {
				Type:     schema.TypeInt,
				Optional: true,
			},

			"authentication_plugin": {
				Type:         schema.TypeString,
				Optional:     true,
				Default:      nativePasswords,
				ValidateFunc: validation.StringInSlice([]string{cleartextPasswords, nativePasswords, aadAuthentication}, true),
			},

			"aad_auth_client_id": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "Azure AD Client ID, required when using AAD Auth Plugin",
				ValidateFunc: validation.StringIsNotEmpty,
			},

			"aad_auth_tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure AD Client ID, required when using AAD Auth Plugin",
			},

			"connect_retry_timeout_sec": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  300,
			},
		},

		DataSourcesMap: map[string]*schema.Resource{
			"mysql_tables": dataSourceTables(),
		},

		ResourcesMap: map[string]*schema.Resource{
			"mysql_database":      resourceDatabase(),
			"mysql_grant":         resourceGrant(),
			"mysql_role":          resourceRole(),
			"mysql_user":          resourceUser(),
			"mysql_user_password": resourceUserPassword(),
			"mysql_sql":           resourceSql(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {

	var endpoint = d.Get("endpoint").(string)

	proto := "tcp"
	if len(endpoint) > 0 && endpoint[0] == '/' {
		proto = "unix"
	}

	var authPlugin = d.Get("authentication_plugin").(string)
	var password = d.Get("password").(string)

	if authPlugin == aadAuthentication {
		authPlugin = cleartextPasswords
		token, err := getAADToken(d, password)
		if err != nil {
			return nil, err
		}
		password = token
	}

	conf := mysql.Config{
		User:                    d.Get("username").(string),
		Passwd:                  password,
		Net:                     proto,
		Addr:                    endpoint,
		TLSConfig:               d.Get("tls").(string),
		AllowNativePasswords:    authPlugin == nativePasswords,
		AllowCleartextPasswords: authPlugin == cleartextPasswords,
	}

	dialer, err := makeDialer(d)
	if err != nil {
		return nil, err
	}

	mysql.RegisterDialContext("tcp", func(ctx context.Context, addr string) (net.Conn, error) {
		return dialer.Dial("tcp", addr)
	})

	mysqlConf := &MySQLConfiguration{
		Config:              &conf,
		MaxConnLifetime:     time.Duration(d.Get("max_conn_lifetime_sec").(int)) * time.Second,
		MaxOpenConns:        d.Get("max_open_conns").(int),
		ConnectRetryTimeout: time.Duration(d.Get("connect_retry_timeout_sec").(int)) * time.Second,
		db:                  nil,
	}

	return mysqlConf, nil
}

func getAADToken(d *schema.ResourceData, password string) (token string, err error) {
	clientId, exists := d.GetOk("aad_auth_client_id")
	if !exists {
		err = fmt.Errorf("aad_auth_client_id is not set and is required when authentication_plugin is aad_auth")
		return
	}
	tenantId, exists := d.GetOk("aad_auth_tenant_id")
	if !exists {
		err = fmt.Errorf("aad_auth_tenant_id is not set and is required when authentication_plugin is aad_auth")
		return
	}
	clientCredentialsConfig := auth.NewClientCredentialsConfig(clientId.(string), password, tenantId.(string))
	clientCredentialsConfig.AADEndpoint = "https://ossrdbms-aad.database.windows.net/.default"
	aadToken, err := clientCredentialsConfig.ServicePrincipalToken()
	if err != nil {
		return
	}
	token = aadToken.Token().AccessToken
	return
}

var identQuoteReplacer = strings.NewReplacer("`", "``")

func makeDialer(d *schema.ResourceData) (proxy.Dialer, error) {
	proxyFromEnv := proxy.FromEnvironment()
	proxyArg := d.Get("proxy").(string)

	if len(proxyArg) > 0 {
		proxyURL, err := url.Parse(proxyArg)
		if err != nil {
			return nil, err
		}
		proxy, err := proxy.FromURL(proxyURL, proxy.Direct)
		if err != nil {
			return nil, err
		}

		return proxy, nil
	}

	return proxyFromEnv, nil
}

func quoteIdentifier(in string) string {
	return fmt.Sprintf("`%s`", identQuoteReplacer.Replace(in))
}

func serverVersion(db *sql.DB) (*version.Version, error) {
	var versionString string
	err := db.QueryRow("SELECT @@GLOBAL.innodb_version").Scan(&versionString)
	if err != nil {
		return nil, err
	}

	return version.NewVersion(versionString)
}

func serverVersionString(db *sql.DB) (string, error) {
	var versionString string
	err := db.QueryRow("SELECT @@GLOBAL.version").Scan(&versionString)
	if err != nil {
		return "", err
	}

	return versionString, nil
}

func connectToMySQL(conf *MySQLConfiguration) (*sql.DB, error) {

	dsn := conf.Config.FormatDSN()
	var db *sql.DB
	var err error

	// When provisioning a database server there can often be a lag between
	// when Terraform thinks it's available and when it is actually available.
	// This is particularly acute when provisioning a server and then immediately
	// trying to provision a database on it.
	retryError := resource.Retry(conf.ConnectRetryTimeout, func() *resource.RetryError {
		db, err = sql.Open("mysql", dsn)
		if err != nil {
			return resource.RetryableError(err)
		}

		err = db.Ping()
		if err != nil {
			return resource.RetryableError(err)
		}

		return nil
	})

	if retryError != nil {
		return nil, fmt.Errorf("could not connect to server: %s", retryError)
	}
	db.SetConnMaxLifetime(conf.MaxConnLifetime)
	db.SetMaxOpenConns(conf.MaxOpenConns)
	return db, nil
}
