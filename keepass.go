package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/howeyc/gopass"
	"github.com/tobischo/gokeepasslib/v3"
	"gopkg.in/yaml.v2"
)

var (
	auths = make(map[string]auth)
)

func init() {

	yamlFile, err := ioutil.ReadFile("conf.yaml")
	if os.IsNotExist(err) {
		return
	} else if err != nil {
		panic(err)
	}

	config := &KeepassConfig{}
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		panic(err)
	}
	_, err = os.Stat(config.Database)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Enter Password for database %s: ", config.Database)
	// Silent. For printing *'s use gopass.GetPasswdMasked()
	password, err := gopass.GetPasswdMasked()
	file, _ := os.Open(config.Database)
	defer file.Close()
	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(string(password))
	_ = gokeepasslib.NewDecoder(file).Decode(db)

	db.UnlockProtectedEntries()
	groups := db.Content.Root.Groups

	for u, e := range config.Urls {

		auth := extractAuth(groups, e)
		if auth != nil {
			auths[u] = *auth
		}
	}
}

func applyBasicOutFor(req *http.Request) {
	if len(auths) == 0 {
		return
	}
	auth, ok := auths[req.URL.Hostname()]

	if !ok {
		return
	}

	req.SetBasicAuth(auth.username, auth.password)
}

func getGroup(groups []gokeepasslib.Group, paths []string) *gokeepasslib.Group {
	for _, g := range groups {
		if g.Name == paths[0] {
			if len(paths) == 1 {
				return &g
			}
			if len(paths) > 0 {
				return getGroup(g.Groups, paths[1:])
			}
		}
	}
	return nil
}

func getEntry(group *gokeepasslib.Group, title string) *gokeepasslib.Entry {
	for _, e := range group.Entries {
		if e.GetTitle() == title {
			return &e
		}
	}
	return nil
}

func extractAuth(groups []gokeepasslib.Group, entry *Entry) *auth {
	g := getGroup(groups, entry.GroupPath)
	var a *auth
	if g != nil {
		e := getEntry(g, entry.Title)
		if e != nil {
			a = &auth{
				username: e.GetContent("UserName"),
				password: e.GetPassword(),
			}
		}
	}
	return a
}

// KeepassConfig keepass configuration
type KeepassConfig struct {
	Database string            `yaml:"database"`
	Urls     map[string]*Entry `yaml:"urls"`
}

// Entry a keepass entry
type Entry struct {
	GroupPath []string `yaml:"groupPath"`
	Title     string   `yaml:"title"`
}

type auth struct {
	username string
	password string
}
