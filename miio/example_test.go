package miio_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Yonsm/misgo/account"
	"github.com/Yonsm/misgo/miio"
)

// Example shows the cloud MiIO library entry points used by the misgo command
// line. It has no Output comment, so it is compiled but not executed because it
// needs live credentials.
func Example() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	acct := account.New(os.Getenv("MI_USER"), os.Getenv("MI_PASS"),
		account.WithTokenPath(filepath.Join(home, ".mi.token")))
	defer acct.Close()

	value, err := miio.New(acct, "cn").MIoTGetProp(context.Background(), os.Getenv("MI_DID"), miio.IID{SIID: 2, PIID: 1})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(value)
}
