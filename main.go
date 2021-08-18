package main

import (
	"fmt"
	"net/http"
)

func homeRoot(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello!")
}

func main() {
	http.HandleFunc("/", homeRoot)
	http.ListenAndServe(":8080", nil)
}
