package app

import (
	"PhoneBook/utils"
	"net/http"
	"strings"
)

var JwtAuthentication= func(next http.Handler) http.Handler{
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		noAuth:=[]string{"/api/user/new","/api/user/login"}
		requestPath:=r.URL.Path

		for _,value := range noAuth {
			if value == requestPath {
				next.ServeHTTP(w,r)
				return
			}
		}
		response:=make(map[string] interface{})
		tokenHeader:=r.Header.Get("Authorization")
		if(tokenHeader==""){
				response=utils.Message(false,"token not found")
				w.WriteHeader(http.StatusForbidden)
				w.Header().Add("Content-Type","application/json")
				utils.Respond(w,response)
		}
		splitted := strings.Split(tokenHeader, " ")
		if len(splitted)!=2{
			response=utils.Message(false,"Invalid/Malformed auth token")
			w.Header().Add("Content-Type","application/json")
			w.WriteHeader(http.StatusForbidden)
			utils.Respond(w,response)
		}
		tokenPart:=splitted[1]
		tk := &models.Token{}
	})
}
