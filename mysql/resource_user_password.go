package mysql

import (
	"fmt"
	"log"

	"github.com/gofrs/uuid"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceUserPassword() *schema.Resource {
	return &schema.Resource{
		Create: SetUserPassword,
		Read:   ReadUserPassword,
		Delete: DeleteUserPassword,
		Schema: map[string]*schema.Schema{
			"user": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"host": {
				Type:     schema.TypeString,
				Optional: true,
				ForceNew: true,
				Default:  "localhost",
			},
			"password": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},
		},
	}
}

func SetUserPassword(d *schema.ResourceData, meta interface{}) error {
	db, err := meta.(*MySQLConfiguration).GetDbConn()
	if err != nil {
		return err
	}

	uuid, err := uuid.NewV4()
	if err != nil {
		return err
	}

	password := uuid.String()
	d.Set("password", password)

	/* ALTER USER syntax introduced in MySQL 5.7.6 deprecates SET PASSWORD (GH-8230) */
	serverVersion, err := serverVersion(db)
	if err != nil {
		return fmt.Errorf("could not determine server version: %s", err)
	}
	ver, _ := version.NewVersion("5.7.6")
	var stmtSQL string
	if serverVersion.LessThan(ver) {
		stmtSQL = fmt.Sprintf("SET PASSWORD FOR '%s'@'%s' = PASSWORD('%s')",
			d.Get("user").(string),
			d.Get("host").(string),
			password)
	} else {
		stmtSQL = fmt.Sprintf("ALTER USER '%s'@'%s' IDENTIFIED BY '%s'",
			d.Get("user").(string),
			d.Get("host").(string),
			password)
	}

	log.Println("Executing statement:", stmtSQL)
	_, err = db.Exec(stmtSQL)
	if err != nil {
		return err
	}
	user := fmt.Sprintf("%s@%s",
		d.Get("user").(string),
		d.Get("host").(string))
	d.SetId(user)
	return nil
}

func ReadUserPassword(d *schema.ResourceData, meta interface{}) error {
	// This is obviously not possible.
	return nil
}

func DeleteUserPassword(d *schema.ResourceData, meta interface{}) error {
	// We don't need to do anything on the MySQL side here. Just need TF
	// to remove from the state file.
	return nil
}
