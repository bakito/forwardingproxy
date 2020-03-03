package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"syscall"

	"github.com/tobischo/gokeepasslib/v3"
	"golang.org/x/crypto/ssh/terminal"
	"gopkg.in/yaml.v2"
)

var (
	auths  = map[string]string{"lh": "Shops/paravan.ch"}
	config *KeepassConfig
	groups []gokeepasslib.Group
)

func init() {

	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if os.IsNotExist(err) {
		return
	} else if err != nil {
		panic(err)
	}

	config = &KeepassConfig{}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		panic(err)
	}
	_, err = os.Stat(config.Database)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Enter Password for database %s: ", config.Database)
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		panic(err)
	}

	file, _ := os.Open(config.Database)
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(string(bytePassword))
	_ = gokeepasslib.NewDecoder(file).Decode(db)

	db.UnlockProtectedEntries()
	groups = db.Content.Root.Groups[0].Groups

}

func applyBasicOutFor(req *http.Request) {
	if len(groups) == 0 || config == nil {
		return
	}
	entry, ok := config.Urls[req.URL.Hostname()]

	if !ok {
		return
	}

	for _, g := range groups {
		if g.Name == entry.Group {
			for _, e := range g.Entries {
				if e.GetTitle() == entry.Title {
					req.SetBasicAuth(e.GetContent("UserName"), e.GetPassword())
				}
			}
		}
	}
}

// KeepassConfig keepass configuration
type KeepassConfig struct {
	Database string            `yaml:"database"`
	Urls     map[string]*Entry `yaml:"urls"`
}

// Entry a keepass entry
type Entry struct {
	Group string `yaml:"group"`
	Title string `yaml:"title"`
}
