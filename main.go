package main

import (
	"context"
	"encoding/json"
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	mongo "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strconv"
	"time"
)


func main() {
	mux := http.NewServeMux()
	mux.Handle("/users", &userHandler{})
	mux.Handle("/refresh", &refreshHandler{})
	http.ListenAndServe(":8080", mux)
}

const (
	secret_alert = "alert"
	secret_refresh = "refresh"
)

type Result struct {
	Id	int64 		`json:"id"`
	Tokens [][]byte	`json:"tokens"`
}

type refreshHandler struct{}


func CreateTokens(id int64) (TokenDetails, error) {
	var err error
	var td TokenDetails
	AtExpires := time.Now().Add(time.Minute * 15).Unix()
	RtExpires := time.Now().Add(time.Hour * 24 * 7).Unix()

	atClaims := jwt.MapClaims{}
	atClaims["authorized"] = true
	atClaims["user_id"] = id
	atClaims["exp"] = AtExpires
	at := jwt.NewWithClaims(jwt.SigningMethodHS512, atClaims)
	td.AccessToken, err = at.SignedString([]byte(secret_alert))
	if err != nil {
		err = fmt.Errorf("can't create access token token: %v", err)
		return td, err
	}

	rtClaims := jwt.MapClaims{}
	rtClaims["authorized"] = true
	rtClaims["user_id"] = id
	rtClaims["exp"] = RtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodHS512, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(secret_refresh))
	if err != nil {
		err = fmt.Errorf("can't create access token token: %v", err)
		return td, err
	}

	td.RefreshToken = td.RefreshToken + td.AccessToken[len(td.AccessToken)- 6:]
	return td, nil
}

func (h *refreshHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var td TokenDetails
	if err := json.NewDecoder(r.Body).Decode(&td); err != nil {
		w.Write([]byte("internal server error"))
		return
	}
	if td.RefreshToken[len(td.RefreshToken) - 6:] != td.AccessToken[len(td.AccessToken) - 6:] {
		fmt.Println("Не совпадает пара токенов")
		w.Write([]byte("internal server error"))
		return
	}
	_ , err := jwt.Parse(td.AccessToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret_alert), nil
	})
	if err != nil {
		fmt.Printf("don't valid access token: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	tokenRefresh := td.RefreshToken[:len(td.RefreshToken) - 6]
	token, err := jwt.Parse(tokenRefresh, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(secret_refresh), nil
	})
	if err != nil {
		fmt.Printf("problem with parse: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}

	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		fmt.Printf("problem with valid: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Printf("problem with claims: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	id, ok := claims["user_id"]
	if !ok {
		fmt.Printf("problem with uder_id: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	guid := int64(id.(float64))

	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://jwt:uu@cluster0.wnpif.mongodb.net/auth?retryWrites=true&w=majority"))
	if err != nil {
		fmt.Printf("can't get new client: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}

	err = client.Connect(context.TODO())
	if err != nil {
		fmt.Printf("can't Connect: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		fmt.Printf("can't ping: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	collection := client.Database("auth").Collection("tokens")
	var result Result
	err = collection.FindOne(context.TODO(), bson.M{"id": guid}).Decode(&result)
	var tokenBytes []byte
	if len(td.RefreshToken) > 70 {
		tokenBytes = []byte(td.RefreshToken[len(td.RefreshToken) - 70:])
	} else {
		tokenBytes = []byte(td.RefreshToken)
	}
	number := -1
	for i, tokendb := range(result.Tokens) {
		if err := bcrypt.CompareHashAndPassword(tokendb, tokenBytes); err == nil {
			number = i
			break
		}
	}
	if number == -1 {
		fmt.Println("don't find token")
		w.Write([]byte("internal server error"))
		return
	}
	newTd, err := CreateTokens(guid)
	if err != nil {
		fmt.Fprintf(w, "problem with CreateTokens: %s", err)
		w.Write([]byte("internal server error"))
		return
	}
	var bytes []byte
	if len(td.RefreshToken) > 70 {
		bytes, err = bcrypt.GenerateFromPassword([]byte(newTd.RefreshToken[len(newTd.RefreshToken) - 70:]),bcrypt.DefaultCost)
	} else {
		bytes, err = bcrypt.GenerateFromPassword([]byte(newTd.RefreshToken),bcrypt.DefaultCost)
	}
	filter := bson.D{{"id", guid}}
	update := bson.D{
		{"$set", bson.D {
			{"tokens"+"."+strconv.Itoa(number), bytes},
		}},
	}
	_, err = collection.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("internal server error"))
		return
	}
	err = client.Disconnect(context.TODO())
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("internal server error"))
		return
	}
	tokens, err := json.Marshal(td)
	if err != nil {
		fmt.Fprintf(w, "can't marshal tokens: %s", err)
		return
	}
	w.Write(tokens)
}

type userHandler struct {}


type TokenDetails struct {
	 AccessToken	string	`json:"access_token"`
	 RefreshToken	string	`json:"refresh_token"`
}

type User struct {
	Id		string `json:"id"`
}

func (h *userHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		return
	}
	var err error
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		fmt.Println(err)
		w.Write([]byte("internal server error"))
		return
	}
	guid, err := strconv.ParseInt(user.Id, 10, 64)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("internal server error"))
		return
	}



	td, err := CreateTokens(guid)
	if err != nil {
		fmt.Fprintf(w, "problem with CreateTokens: %s", err)
		w.Write([]byte("internal server error"))
		return
	}
	tokens, err := json.Marshal(td)
	if err != nil {
		fmt.Fprintf(w, "can't marshal tokens: %s", err)
		w.Write([]byte("internal server error"))
		return
	}
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb+srv://jwt:uu@cluster0.wnpif.mongodb.net/auth?retryWrites=true&w=majority"))
	if err != nil {
		fmt.Printf("can't get new client: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}

	err = client.Connect(context.TODO())
	if err != nil {
		fmt.Printf("can't Connect: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}

	err = client.Ping(context.TODO(), nil)
	if err != nil {
		fmt.Printf("can't ping: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	collection := client.Database("auth").Collection("tokens")
	var bytes []byte
	if len(td.RefreshToken) > 70 {
		bytes, err = bcrypt.GenerateFromPassword([]byte(td.RefreshToken[len(td.RefreshToken) - 70:]),bcrypt.DefaultCost)
	} else {
		bytes, err = bcrypt.GenerateFromPassword([]byte(td.RefreshToken),bcrypt.DefaultCost)
	}

	if err != nil {
		fmt.Printf("can't generate from password: %s\n", err)
		w.Write([]byte("internal server error"))
		return
	}
	var result Result

	err = collection.FindOne(context.TODO(), bson.M{"id": guid}).Decode(&result)
	if err != nil {
		_, err = collection.InsertOne(context.TODO(), bson.M{"id": guid, "tokens": [][]byte{bytes}})
		if err != nil {
			fmt.Printf("can't insertone: %s\n", err)
			w.Write([]byte("internal server error"))
			return
		}
	} else {
		filter := bson.D{{"id", guid}}
		var update bson.D
		if len(result.Tokens) >= 5 {
			update = bson.D{
				{"$set", bson.D{
					{"tokens", [][]byte{bytes}},
				}},
			}
		} else {
			update = bson.D{
				{"$push", bson.D{
					{"tokens", bytes},
				}},
			}
		}
		_, err := collection.UpdateOne(context.TODO(), filter, update)
		if err != nil {
			fmt.Println(err)
			w.Write([]byte("internal server error"))
			return
		}
	}


	err = client.Disconnect(context.TODO())
	if err != nil {
		fmt.Println(err)
		w.Write([]byte("internal server error"))
		return
	}

	w.Write(tokens)
}