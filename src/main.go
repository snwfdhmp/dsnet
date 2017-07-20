package main

import (
	"crypto/rand"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	RETURN_SUCCESS = 0
	RETURN_KICK    = -2
	RETURN_EMPTY   = -1

	RED       = "\033[1;31m"
	GREEN     = "\033[1;32m"
	YELLOW    = "\033[1;33m"
	BLUE      = "\033[1;36m"
	ITALIC    = "\033[3m"
	END_STYLE = "\033[0m"

	INFO    = "\033[1;36m"
	ALERT   = "\033[1;31m"
	SUCCESS = "\033[1;32m"
	WARNING = "\033[1;33m"

	MAX_FAIL = 10
)

var (
	LISTENING_PORT = "8095"
	Role           string
	Nodes          []Node
	Network        string
)

type Node struct {
	Token       string
	CurrentUser string
	Ip          string
	Port        string
	ServerPort  string
	MyToken     string
	Blame       int
	Banned      bool
	Connected   bool
	FailCount   int
}

type forEachFunc func(Node)

// type Task struct [{
// 	Command string
// }]

func ForwardRequest(node Node, r *http.Request) {
	url := fmt.Sprintf("%v", r.URL)
	http.Get(getServerAddr(node) + url)
}

func ExecuteRole(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//before call
		url := fmt.Sprintf("%v", r.URL)
		if len(url) >= 5 { //special cases
			if url[:5] == "/role" || url[:5] == "/ping" { //@todo beautify
				handler.ServeHTTP(w, r)
				return
			}
		} else if len(url) >= 7 {
			if url[:7] == "/expand" {
				handler.ServeHTTP(w, r)
				return
			}
		}

		if Role == "node" {
			handler.ServeHTTP(w, r)
		} else if Role == "shouter" {
			for _, node := range Nodes {
				if node.Banned || node.ServerPort == "" {
					continue
				} else {
					ForwardRequest(node, r)
				}
			}
		}

		//after call
	})
}
func PrintError(str string) {
	fmt.Print(RED + str + END_STYLE)
}

func PrintSuccess(str string) {
	fmt.Print(GREEN + str + END_STYLE)
}

func PrintWarning(str string) {
	fmt.Print(YELLOW + str + END_STYLE)
}

func PrintInfo(str string) {
	fmt.Print(BLUE + str + END_STYLE)
}

func randToken() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func searchNode(token string) (Node, int) {
	for i, node := range Nodes {
		if node.Token == token {
			if node.Banned == true {
				return node, RETURN_KICK
			}
			return Nodes[i], i
		}
	}
	return Node{}, RETURN_EMPTY
}

func SplitAddr(r *http.Request) (string, string) {
	arr := strings.Split(r.RemoteAddr, ":")
	ip := arr[0]
	port := arr[1]
	return ip, port
}

func AnalyzeNode(w http.ResponseWriter, r *http.Request, node Node) (Node, bool) {
	ip, port := SplitAddr(r)

	if node.Port != port {
		node.Blame++
		fmt.Println(WARNING+"!", node.Token, "changed port", node.Port, "=>", port, "blame", node.Blame, END_STYLE)
		node.Port = port
	}
	if node.Ip != ip {
		node.Blame += 2
		fmt.Println(WARNING+"!", node.Token, "changed ip", node.Ip, "=>", ip, "blame", node.Blame, END_STYLE)
		node.Ip = ip
	}

	if node.Blame >= 3 {
		node.Banned = true
	}

	if node.Banned {
		fmt.Println(ALERT+"& banned", node.Token+END_STYLE)
		return node, false
	}

	io.WriteString(w, "pong")
	return node, true
}

func Ping(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	token := ps.ByName("token")
	node, id := searchNode(token)

	if !checkId(id, token) {
		return
	}

	fmt.Println(WARNING+". ping from", node.Token, "blame", node.Blame, END_STYLE)

	Nodes[id], _ = AnalyzeNode(w, r, node)
}

func PrintList(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	fmt.Println(INFO + ". nodes:" + END_STYLE)
	for _, node := range Nodes {
		fmt.Println("-", node.Ip, "token", node.Token, "myToken", node.MyToken)
	}
}

func Status(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Println(INFO+"total nodes:", len(Nodes), END_STYLE)
}

func Tap(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	ip := ps.ByName("ip")
	port := ps.ByName("port")

	dest := ip + ":" + port

	fmt.Println(WARNING+">@ tap requested for", INFO+dest+END_STYLE)

	found := false

	for _, n := range Nodes {
		if n.Ip == ip && n.ServerPort == port {
			found = true
			break
		}
	}

	if found == true {
		fmt.Println(WARNING+"_. already added", ip+":"+port)
		return
	}

	node := Node{
		ServerPort: port,
		Ip:         ip,
		Blame:      0,
		Banned:     false,
		FailCount:  0,
	}

	token := GetHelloToken(node)

	node.MyToken = token

	Nodes = append(Nodes, node)

	fmt.Println(SUCCESS+">. token received:", INFO+token+END_STYLE)
	io.WriteString(w, token)

	addr := getServerAddr(node)
	http.Get(addr + "/connect/" + node.MyToken + "/" + LISTENING_PORT)
}

func getServerAddr(node Node) string {
	return "http://" + node.Ip + ":" + node.ServerPort
}

func readResp(resp *http.Response) string {
	body, err := ioutil.ReadAll(resp.Body)
	checkErr(err)

	return string(body)
}

func getBody(url string) string {
	resp, err := http.Get(url)
	checkErr(err)
	defer resp.Body.Close()

	return readResp(resp)
}

func GetHelloToken(node Node) string {
	if node.ServerPort == "" {
		return "" //@todo handle errors
	}
	url := getServerAddr(node) + "/hello"

	return getBody(url)
}

func PingAll() {
	for i, node := range Nodes {
		if node.Banned {
			continue
		}
		if node.MyToken != "" {
			fmt.Print(INFO + ". pinging " + node.Token + " ... " + END_STYLE)
			resp, err := http.Get(getServerAddr(node) + "/ping/" + node.MyToken)

			if err != nil {
				node.FailCount++
				fmt.Println(RED + "failed to connect (" + strconv.Itoa(node.FailCount) + "/" + strconv.Itoa(MAX_FAIL) + ")" + END_STYLE)
				Nodes[i] = node
				if node.FailCount >= MAX_FAIL {
					fmt.Println(RED+"! deleted", node.Token, "from Nodes (too many fails)")
					Nodes = append(Nodes[:i], Nodes[i+1:]...)
				}
				continue
			}

			body := readResp(resp)
			if body == "pong" {
				fmt.Println(GREEN + "pong" + END_STYLE)
			} else {
				fmt.Println(RED + body + END_STYLE)
			}
		}
	}
}

func ConnectNode(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	token := ps.ByName("token")
	port := ps.ByName("port")

	fmt.Println(WARNING+">$", INFO+token+WARNING, "wants to connect"+END_STYLE)

	node, id := searchNode(token)

	if !checkId(id, token) {
		return
	}

	if node.Connected != true {
		node.ServerPort = port

		if node.MyToken == "" {
			fmt.Println(WARNING+"<@ claim request sent to", INFO+token+END_STYLE)
			node.MyToken = getBody(getServerAddr(node) + "/claim/" + token)
		}
		node.Connected = true

		fmt.Println(SUCCESS+"-@ connected to", INFO+node.Token+SUCCESS, "with token", INFO+node.MyToken+END_STYLE)

		applyChanges(node, id)
	} else {
		fmt.Println(ALERT+"!. already connected to", node.Ip)
	}

}

func StartCronPing() {
	ticker := time.NewTicker(1 * time.Second)
	quit := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				PingAll()
			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()
}

func Claim(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	myToken := ps.ByName("token")

	for i, node := range Nodes {
		if node.MyToken == myToken {
			fmt.Println(SUCCESS+">@ claimed token", INFO+myToken+SUCCESS, "by", INFO+node.Ip+":"+node.ServerPort+END_STYLE)
			node.Token = randToken()
			node.Ip, node.Port = SplitAddr(r)
			node.FailCount = 0

			io.WriteString(w, node.Token)

			Nodes[i] = node
		}
	}
}

func Hello(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	token := randToken()
	fmt.Println(WARNING+">@ hello from", INFO+r.RemoteAddr+END_STYLE)

	ip, port := SplitAddr(r)

	io.WriteString(w, token)
	fmt.Println(SUCCESS+"<@ assigned", INFO+token+SUCCESS, "to", INFO+r.RemoteAddr+END_STYLE)

	Nodes = append(Nodes, Node{
		Token:       token,
		CurrentUser: "",
		Ip:          ip,
		Port:        port,
		Blame:       0,
		Banned:      false,
	})
}

func forEachValidNode(fn forEachFunc) {
	for _, node := range Nodes {
		if node.Banned == true {
			continue
		}

		fn(node)
	}
}

func ShareNodesToNode(target Node) {
	addr := getServerAddr(target)
	for _, node := range Nodes {
		if node.Banned == true || node.ServerPort == "" {
			continue
		}
		if node != target {
			http.Get(addr + "/tap/" + node.Ip + "/" + node.ServerPort)
		}
	}
}

func ShareNodesToNodeWithExpand(target Node) {
	ShareNodesToNode(target)
	http.Get(getServerAddr(target) + "/expand/" + Network)
}

func SharesNodesThroughNetwork(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	forEachValidNode(ShareNodesToNode)
}

func ExpandNetwork(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	network := ps.ByName("networkName")
	fmt.Println(WARNING+">$ asked to join", INFO+network+END_STYLE)
	if network == Network {
		fmt.Println(WARNING+"_. already part of", INFO+network+END_STYLE)
		return
	} else {
		Network = network
		fmt.Println("_@ joining", INFO+network+END_STYLE)
		forEachValidNode(ShareNodesToNodeWithExpand)
	}
}

func PingAllRoute(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	go PingAll()
}

func StartPingAllRoute(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	StartCronPing()
}

func RoleChanger(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	role := ps.ByName("role")

	fmt.Println(WARNING + ">! role change requested (" + INFO + Role + WARNING + "=>" + INFO + role + WARNING + ")")

	if role == Role {
		fmt.Println(WARNING+"_! role is already", INFO+role+WARNING)
		return
	}
	Role = role

	if Role == "shouter" {
		for _, node := range Nodes {
			if node.Banned {
				continue
			}
			http.Get(getServerAddr(node) + "/role/node")
		}
	}

	fmt.Println(SUCCESS+"_@ role changed to", INFO+Role)
}

func main() {
	Role = "node"
	if len(os.Args) == 2 {
		LISTENING_PORT = os.Args[1]
	}
	fmt.Println("* listening on", LISTENING_PORT)

	router := httprouter.New()

	router.GET("/hello", Hello)
	router.GET("/ping/:token", Ping)
	router.GET("/connect/:token/:port", ConnectNode)
	router.GET("/claim/:token", Claim)
	router.GET("/status", Status)
	router.GET("/list", PrintList)
	router.GET("/ping", PingAllRoute)
	router.GET("/start/ping", StartPingAllRoute)
	router.GET("/tap/:ip/:port", Tap)
	router.GET("/share", SharesNodesThroughNetwork)
	router.GET("/expand/:networkName", ExpandNetwork)
	router.GET("/role/:role", RoleChanger)

	log.Fatal(http.ListenAndServe(":"+LISTENING_PORT, ExecuteRole(router)))
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func checkId(id int, token string) bool {
	if id < RETURN_SUCCESS {
		switch id {
		case RETURN_EMPTY:
			fmt.Println(WARNING+"! fake token :", token+END_STYLE)
			break
		case RETURN_KICK:
			fmt.Println(ALERT+"/ kicked", token+END_STYLE)
			break
		default:
			fmt.Println(WARNING + "? unknown error" + END_STYLE)
			break
		}
		return false
	}
	return true
}

func applyChanges(node Node, id int) {
	Nodes[id] = node
}
