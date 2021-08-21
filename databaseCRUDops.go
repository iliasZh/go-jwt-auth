package main

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type DBRecord struct {
	UserUUID         uuid.UUID `bson:"_id"`
	RefreshTokenHash []byte    `bson:"token_hash"`
}

func createDatabaseRecord(userUUID uuid.UUID, hashedToken []byte) error {
	record := DBRecord{
		UserUUID:         userUUID,
		RefreshTokenHash: hashedToken,
	}

	document, err := bson.Marshal(record)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	tokenCollection := getTokenCollection()
	_, err = tokenCollection.InsertOne(ctx, document)
	if err != nil {
		return err
	}

	return nil
}

func retrieveDatabaseRecord(userUUID uuid.UUID) (DBRecord, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	tokenCollection := getTokenCollection()
	result := tokenCollection.FindOne(ctx, bson.M{"_id": userUUID})

	if err := result.Err(); err != nil {
		return DBRecord{}, err
	}

	var record DBRecord
	err := result.Decode(&record)
	return record, err
}

func updateDatabaseRecord(userUUID uuid.UUID, hashedToken []byte) (updated bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	tokenCollection := getTokenCollection()

	var result *mongo.UpdateResult
	result, err = tokenCollection.UpdateOne(
		ctx,
		bson.M{"_id": userUUID},
		bson.D{{
			Key:   "$set",
			Value: bson.D{{Key: "token_hash", Value: hashedToken}},
		}},
	)

	if err != nil {
		return
	}
	updated = result.ModifiedCount == 1
	return
}

// returns true if deleted
func deleteDatabaseRecord(userUUID uuid.UUID) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	tokenCollection := getTokenCollection()
	result, err := tokenCollection.DeleteOne(ctx, bson.M{"_id": userUUID})
	if err != nil {
		return result.DeletedCount == 1, err
	}
	return result.DeletedCount == 1, nil
}
