package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

func main() {
	url := "http://www.example.com"
	wordlistPath := "wordlist.txt"

	wordlist, err := ioutil.ReadFile(wordlistPath)
	if err != nil {
		fmt.Printf("Erro ao ler a wordlist: %s\n", err.Error())
		return
	}

	payloads := strings.Split(string(wordlist), "\n")

	for _, payload := range payloads {
		payload = strings.TrimSpace(payload)
		if payload != "" {
			fullURL := fmt.Sprintf("%s/%s", url, payload)
			resp, err := http.Get(fullURL)
			if err != nil {
				fmt.Printf("Erro ao fazer a requisição HTTP: %s\n", err.Error())
				continue
			}
			defer resp.Body.Close()

			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				fmt.Printf("Erro ao ler a resposta HTTP: %s\n", err.Error())
				continue
			}

			// Verificar se a resposta contém XSS
			if hasXSS(body) {
				fmt.Printf("Vulnerabilidade encontrada: %s\n", fullURL)
			}
		}
	}
}

func hasXSS(response []byte) bool {
	doc, err := html.Parse(strings.NewReader(string(response)))
	if err != nil {
		return false
	}

	return detectXSS(doc)
}

func detectXSS(n *html.Node) bool {
	if n.Type == html.ElementNode {
		switch n.DataAtom {
		case atom.Script, atom.Img:
			for _, attr := range n.Attr {
				if strings.EqualFold(attr.Key, "onerror") {
					return true
				}
			}
		}
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if detectXSS(c) {
			return true
		}
	}

	return false
}
