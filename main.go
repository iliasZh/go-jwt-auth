package main

import (
	"context"
	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func handleRequests() {
	myRouter := mux.NewRouter().StrictSlash(true)

	myRouter.HandleFunc("/", homePage).Methods("GET")
	myRouter.HandleFunc("/get-tokens", getTokens).Methods("GET")
	myRouter.HandleFunc("/refresh-tokens", refreshTokens).Methods("POST")

	addr := ":" + viperGetString("server_port")
	log.Fatal(http.ListenAndServe(addr, myRouter))
}

func main() {
	viperInit()

	mongoClientInit()
	connectToDatabase()
	defer mongoClient.Disconnect(context.Background())

	handleRequests()
}
