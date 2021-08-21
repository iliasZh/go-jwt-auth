package main

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var mongoClient *mongo.Client

func mongoClientInit() {
	if mongoClient != nil {
		log.Fatal("client has already been initialized")
	}

	dbURI := viperGetString("db_uri")
	var err error
	mongoClient, err = mongo.NewClient(options.Client().ApplyURI(dbURI))
	if err != nil {
		log.Fatal("error while creating a mongo client: ", err)
	}
}

func connectToDatabase() {
	if mongoClient == nil {
		log.Fatal("mongoClient is nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := mongoClient.Connect(ctx); err != nil {
		log.Fatal("error while connecting to the db: ", err)
	}
}

func getTokenCollection() *mongo.Collection {
	dbName := viperGetString("db_name")
	collectionName := viperGetString("db_token_collection")

	database := mongoClient.Database(dbName)
	refreshTokenCollection := database.Collection(collectionName)
	return refreshTokenCollection
}

func registerRefreshTokenInDatabase(userUUID uuid.UUID, token RefreshToken) error {
	hashedToken, err := token.bcryptHash()
	if err != nil {
		return err
	}

	updated, err := updateDatabaseRecord(userUUID, hashedToken)

	if err != nil {
		return err
	}

	if updated {
		return nil
	}

	err = createDatabaseRecord(userUUID, hashedToken)
	if err != nil {
		return err
	}
	return nil
}
