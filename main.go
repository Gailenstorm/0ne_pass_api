package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"

	"golang.org/x/crypto/argon2"
)

type Request struct {
	Password string `json:"password"`
	Salt     string `json:"salt"`
	Size     uint32 `json:"size"`
}

type Response struct {
	Hashed string `json:"hashed"`
	Size   uint32 `json:"size"`
}

type ErrorResponse struct {
	Errors []string `json:"errors"`
}

var DefaultParams = &Params{
	Memory:      64 * 1024,
	Iterations:  3,
	Parallelism: 2,
}

type Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
}

var (
	ErrBadRequest       = errors.New("The request is malformed")
	ErrPasswordTooShort = errors.New("The password is too short")
	ErrSaltTooShort     = errors.New("The salt is too short")
)

func errorToStringArray(err error) []string {
	errs := make([]string, 1)
	errs[0] = err.Error()
	return errs
}

func errorArrayToStringArray(errs []error) []string {
	strErrs := make([]string, len(errs))
	for i, err := range errs {
		strErrs[i] = err.Error()
	}
	return strErrs
}

func (request *Request) convertB64Size() {
	request.Size = uint32(math.Floor(3 * (float64(request.Size) / 4)))
}

func (response *Response) createHash(request *Request) {
	sizeWanted := request.Size
	request.convertB64Size()
	for response.Size < sizeWanted {
		key := argon2.IDKey([]byte(request.Password), []byte(request.Salt), DefaultParams.Iterations, DefaultParams.Memory, DefaultParams.Parallelism, request.Size)
		response.Hashed = base64.RawStdEncoding.EncodeToString(key)
		response.Size = uint32(len(response.Hashed))
		request.Size = request.Size + 1
	}
}

func (request *Request) validate() []error {
	errs := make([]error, 0)

	if len(request.Password) < 8 {
		errs = append(errs, ErrPasswordTooShort)
	}
	if len(request.Salt) < 8 {
		errs = append(errs, ErrSaltTooShort)
	}
	if request.Size < 8 {
		request.Size = 8
	}
	return errs
}

func handleErrResponse(err error, w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusBadRequest)
	errResponse := ErrorResponse{}
	errResponse.Errors = errorToStringArray(err)
	responseJSON, err := json.Marshal(errResponse)
	if err != nil {
		panic(err)
	}
	(*w).Write(responseJSON)
}

func handleErrsResponse(errs *[]error, w *http.ResponseWriter) {
	(*w).WriteHeader(http.StatusBadRequest)
	errResponse := ErrorResponse{}
	errResponse.Errors = errorArrayToStringArray(*errs)
	responseJSON, err := json.Marshal(errResponse)
	if err != nil {
		panic(err)
	}
	(*w).Write(responseJSON)
}

func handleResponse(response *Response, w *http.ResponseWriter) {
	responseJSON, err := json.Marshal(response)
	if err != nil {
		handleErrResponse(err, w)
		return
	}
	(*w).WriteHeader(http.StatusOK)
	(*w).Write(responseJSON)
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	request := Request{}
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		handleErrResponse(err, &w)
		return
	}

	errs := request.validate()
	if len(errs) != 0 {
		handleErrsResponse(&errs, &w)
		return
	}

	response := Response{}
	response.createHash(&request)

	handleResponse(&response, &w)
}

func main() {
	http.HandleFunc("/api", handleRequest)
	http.ListenAndServe("127.0.0.1:8000", nil)
}
